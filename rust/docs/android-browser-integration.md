# Android 的 Safari16 / iOS14 TLS 指纹

2026-11-25：最终主机验收通过，92 个新增／修改文件已合入主源码；四 ABI 优化 AAR 与八个 APK 已封存。
平台仍只有 Android；`safari`、`ios` 是原 Android 节点编辑器已有的
`tls.utls.fingerprint` 配置值。兼容目标是 App 固定 uTLS v1.8.7 的
`HelloSafari_16_0`、`HelloIOS_14`，不是当前 Safari 或 Apple 平台应用。

配置转换为原生 `safari16`、`ios14`，保留普通 TLS、REALITY、VLESS Vision 路径。
普通 TLS 可协商 1.0–1.3；REALITY/Vision 只允许 1.3。配置必须提供该模板完整的
密码套件和密钥交换能力，不用其他浏览器模板替代，也不只改 ClientHello 字节。
不支持的 ECH、QUIC、Naive 模板组合与冲突版本、曲线、套件配置明确拒绝。

| 能力 | Safari16 | iOS14 |
| --- | --- | --- |
| 真实密码套件，不含 GREASE | 20 | 26 |
| 曲线 | X25519、P256、P384、P521 | 相同 |
| 首次真实 key share | X25519 | 相同 |
| 签名列表 | 保留上游 11 项顺序，包括重复的 RSA-PSS/SHA384 | 相同 |
| 证书压缩 | zlib，使用纯 Rust zlib-rs | 不发送压缩扩展 |
| TLS1.2 SHA2-CBC | 不提供 | 6 个 AES/HMAC-SHA256/SHA384 套件 |
| 3DES | ECDHE_RSA、ECDHE_ECDSA、静态 RSA | 相同 |
| Session ticket、ALPS、ECH | 不发送 | 相同 |
| 旧版 TLS 安全重协商 | 普通 TLS 允许一次，校验 RFC5746/证书/ALPN/EMS 连续性 | 相同 |

新密码依赖是 RustCrypto `des=0.9.0`；zlib 使用已有 vendored rustls 的 `zlib-rs` 后端。
AES、HMAC、RSA、ECDSA 和密钥交换仍为 Rust。测试用 Go/OpenSSL/Python 参考实现不进入
Android 成品。`zlib-custom` 仅暴露编解码器；普通连接不会因链接 Safari 所需依赖而
自动发送压缩扩展。ECDSA/SHA1 只进入显式旧握手验证与签名选择，未加入 X.509 信任链
验证算法集合；TLS1.3 的 SHA1 CertificateVerify 继续拒绝。

3DES 每个方向、每个密钥最多处理 2^20 个加密块，即 8 MiB 密文块，计入 MAC 和填充，
不计显式 IV。达到上限后连接永久失败，需要重新建立连接，不能继续使用旧密钥或静默
丢弃已接受数据。因此不承诺与上游无限长 3DES 连接等价。RustCrypto DES 使用数据相关的
S-box 查表，此实现不宣称 3DES 常数时间或已完成密码安全审计。

记录层的失败已改为可传播错误：保留第一次错误，不再 `unwrap` 崩溃；缓冲写只返回
成功进入完整记录的明文长度。无缓冲写返回成功记录前缀长度与明文消耗量，清零其余
输出；后续写、flush、exporter、密钥更新不得使连接恢复。告警本身超限时同样失败，
不会伪报成功关闭。生产异步流保留短写后错误的原始原因与精确字节计数，先排出成功记录前缀，再报告永久错误；失败后不能切到裸流继续发送。

已完成的专项证据：

- `target/android-browser-layout-stage/`：开发/发布模式各 28 个完整首包、116 个 HRR
  场景（232 个 ClientHello），比较全部非随机字节及 GREASE、cookie、padding 关系。
- `target/android-browser-full-interop-stage/`：完整模板下，开发/发布各 54 个 3DES
  成功连接、36 个拒绝；18 个 SHA2-CBC 成功、12 个拒绝；24 个 ECDSA/SHA1 成功、
  21 个拒绝；另有完整重协商、分片和错误绑定矩阵。
- `target/android-browser-tls13-stage/`：开发/发布各 52 个 TLS1.3 成功连接、36 个拒绝，
  涵盖 P521/HRR、zlib、双向认证、65537 字节双向数据和双方 close_notify。
  完整旧套件模板另有 156 个 AES/ChaCha 成功连接和 104 个证书拒绝。
- `target/android-browser-final-stage/budget-evidence/`：内部 13 项预算/失败传播专项
  在开发/发布模式通过，依赖审计为 7 个纯 Rust 活动包；参考 Go 对端的真实边界连接通过。

最终主机验收：密码开发／发布各 176 项、内核 2,874 项（45 项默认忽略）、Quinn 409 项、
Android 主机 36 项、配置 42 项、浏览器生产入口 11 项与独立 Go 协议互通 18 项全部通过。
4 条生产异步流使用真实 8 MiB 3DES 密钥预算，另有 6 项短写／断管回归通过。
首轮参考端误将 Safari／iOS 的 REALITY 曲线列表按 Chrome 校验；已增加显式 profile，
保留 Chrome 的严格校验，并通过独立 uTLS、错误指纹和畸形份额测试。
修正仅涉及 5 个测试文件；未受影响的内核／协议结果及其可执行文件哈希按
`native-v2-provenance.json` 记录，浏览器入口重新编译并全部复测。

本次冻结 3,835 个构建输入，清单 SHA256 为
`62c0e6294864744dce6c7b1254cd613a3ede7b1012c3224c9934db69e025c454`。
开发／发布首包和 HRR 精确对照、armv7 密码源码检查及四 ABI 纯 Rust 活动依赖审计均通过。

最终合并、四 ABI 和 App 包装状态记录在 `target/android-browser-final-stage/status.json`、
`target/android/browser-profiles/status.json`。北京时间 2026-11-25 17:16 完成封存，
最新清单为 `target/android/app-browser-profiles-release/manifest.json`。
AAR 大小 64,426,142 字节，SHA256 为
`fcb2839d73edaf00e9dffd53cccf01a8fce37a26e86a29a7e8f22edd7a5735d8`。

四 ABI 各有 Debug 签名 APK 和未签名 Release APK，138 项 JVM 测试全部通过。
Release/R8/资源压缩/lintVital、14 个 JNI 入口、8 个平台回调及 Release DEX 审计通过；
每个 APK 的内核与封存 AAR 去除无用符号后的内容一致，64 位 ELF 满足 16 KiB 对齐。
同一构建锁下串行构建，采样内存峰值约 4.62 GiB，无 OOM；完整记录位于
`target/build-control/aerobox-core-build-60865.json`。
真机 VPN、Wi-Fi/蜂窝切换以及其他浏览器模板和 Naive Chromium 行为继续由
[剩余工作](remaining-protocol-work.md) 跟踪。

后续 Firefox 合并快照已完成四 ABI 打包；当前最新清单为
`target/android/app-firefox-release/manifest.json`，验证范围见 [Firefox 接入](firefox-integration.md)。
