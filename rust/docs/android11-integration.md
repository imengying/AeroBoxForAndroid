# Android11 TLS 客户端接入

2026-11-23，Android 的 `tls.utls.enabled=true` 与 `fingerprint="android"`
已接入纯 Rust 内核，原生配置名为 `android11`。这里的 Android11 指固定
MetaCubeX/uTLS v1.8.7 的 `HelloAndroid_11_OkHttp` 报文模板，不是 App 最低系统版本。
源码已合入；完整主工程回归状态记录在 `target/android/android11/status.json`。
2026-11-25 已随浏览器指纹合并快照完成四 ABI AAR 与八个 APK 打包，
清单为 `target/android/app-browser-profiles-release/manifest.json`；138 项 JVM 测试通过，
尚无设备测试结果。

## 实现范围

客户端实际支持 TLS1.0、1.1、1.2。旧版本具有独立的 MD5/SHA1 PRF、36 字节转录散列、
RSA 原始 MD5||SHA1 签名、ECDSA/SHA1 签名、旧版 CertificateRequest/CertificateVerify
编码和 Finished 校验。TLS1.0 使用隐式 CBC IV 链和应用记录 1/n-1 分片；TLS1.1 使用显式 IV。
静态 RSA 的 premaster 前两字节来自原始 ClientHello 版本。EMS、exporter、OCSP 数据传递、
RSA/ECDSA 客户端证书认证和双向 close_notify 均接入实际握手。

密码原语来自 RustCrypto；新增 `md-5` 禁用默认功能和可选汇编后端。
普通 provider、普通协议版本列表和服务端没有自动启用旧 TLS。
旧版握手签名不会开放 SHA1 X.509 证书链签名；证书链、名称、有效期和 pin 仍由认证策略检查。
这不代表整个实现已经经过侧信道测量或外部安全审计。

Android11 的 12 个套件、9 个签名算法、3 个组及扩展顺序固定；完整字段见
[独立线协议审计](android11-chrome133-wire-audit.md)。首次 ClientHello 的随机数与 session ID
均为新生成的 32 字节值，默认 SNI 示例生成 192 字节记录。该模板不发送 ALPN、GREASE、
key_share、supported_versions、ticket 或 ECH；会话恢复、早期数据和重协商关闭。

普通 VMess/VLESS/Trojan TLS 使用这一配置。REALITY、Vision、ECH、QUIC 和 Naive 与本模板
不兼容时明确报错。显式版本、套件、曲线或 ALPN 与精确模板冲突也报错；固定上游有时会
覆盖这些用户设置，本实现不把互相矛盾的要求同时报告为生效。TLS1.0/1.1 不能通过普通
默认 TLS 配置意外启用。

## 已执行验证

隔离源码验证通过后合入了 53 个文件，清单与基线备份位于
`target/android/android11/applied-files.json` 和 `source-before/`：

- 49 项密码组件测试：PRF/转录参考向量、CBC 链与失败状态、签名和 provider。
- 3 项报文/策略测试：8 次完整归一化 ClientHello 与固定 uTLS 捕获逐字节比较；
  非显式旧版本、旧版本 AEAD、降级标记和配置冲突拒绝。
- 4 项回归测试：普通 TLS1.2 自定义套件中未知首个签名项；公开分片接口的长度边界；
  TLS1.0/1.1/1.2 静态 RSA 提前应用数据、错误握手消息和认证记录内错误 Finished 拒绝。
- 2 项独立 Go 测试合计 73 次真实连接：旧版四个 Android CBC 套件与全部 12 个 TLS1.2
  套件、无客户端证书/RSA/ECDSA、强制 TLS1.2 RSA/SHA1，以及限定旧版本的 ECDSA CBC
  和静态 RSA。每条连接双向传输 65,537 字节，并核对 exporter、EMS、版本/套件、
  OCSP 数据传递和双向关闭。OCSP 夹具验证传输，不验证吊销判断。

日志在 `target/android11-handshake-stage/evidence/`；最终 overlay 清单 SHA256 为
`3821c139a89ef3e976ece478ce79759bfe638c5aff51238db9862f6656cc01bd`。
独立服务端代码位于 `tests/reference/android11-peer/`，仅测试使用，不进入产品依赖。
主工程验证已于 2026-11-23 15:13 UTC 完成，结果在
`target/android/android11/validation.json`：配置41项、密码开发/发布各111项、Quinn409项、
内核2866项、Go互通18项、浏览器生产路径6项和Android公共入口22项全部通过。
四种Android ABI的纯Rust依赖检查通过，armv7密码/握手源码检查通过。
最终3743个源码文件的快照SHA256为
`7869f0ca08c2d37267f011e85c1c79e8644fa93c6e4e57826f4c18ec31b011cb`。

主工程验证修正了两处问题：普通TLS测试改为在配置策略阶段拒绝旧版本，而保留旧版本名称
解析；离线配置编译器传入实际ALPN列表，防止Android11冲突配置通过检查。
后者只改变配置预检，随后重新编译Android库并通过全部22项公共入口/运行时测试；此前内核
和密码测试沿用未受影响的结果。两次修正、源码差异及各测试对应快照完整记录在
`fixture-correction.json`、`alpn-correction.json` 和 `validation-provenance.json`，
没有把修改前的内核二进制标为修改后的重新构建结果。

所有 Cargo/Go 编译共用构建锁，Cargo jobs=1；构建 cgroup 设置 MemoryHigh=4.5 GiB、
MemoryMax=5 GiB、SwapMax=1 GiB。主代理和一个子代理可以同时处理源码与审查，编译不并发。

后续 Firefox 合并快照已完成四 ABI 打包；当前最新清单为
`target/android/app-firefox-release/manifest.json`，验证范围见 [Firefox 接入](firefox-integration.md)。
