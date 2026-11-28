# TLS 1.2 兼容、Naive 窗口与 TCP Brutal

本轮延续 Rust 2024 与纯 Rust 密码依赖边界。协议实现以原 Android 固定的 sing-box v1.14.4 为准；浏览器指纹本身仍单独验收。

## TLS 1.2

`aerobox-crypto` 增加四个 ECDHE CBC-SHA 套件（RSA/ECDSA 证书 × AES128/256），以及四个静态 RSA 套件（AES128/256 GCM、AES128/256 CBC-SHA）。它们可以由 `tls.cipher_suites` 显式选择，普通默认提供者仍使用原有九个 AEAD 套件。QUIC 和 TLS1.3-only 配置拒绝仅 TLS1.2 的选择。

rustls 密钥块按 client MAC、server MAC、client encryption、server encryption、IV 顺序划分，兼容没有独立 MAC key 的原 AEAD 路径，派生缓冲在释放时清零。CBC 对每个公开密文长度检查所有 1..256 字节填充候选，避免由秘密填充决定哈希长度、内存地址或提前返回；失败统一产生 DecryptError，TLS 连接保持永久错误状态。

CBC 显式 IV 使用独立域分离的 HMAC-SHA256 派生 AES256 密钥，对 record 序号执行 PRF；不复用数据加密密钥，不在逐记录路径请求系统随机数。不可预测性来自握手密钥，序号唯一性由 rustls 记录层保证。这符合 RFC5246 §6.2.3.2 的不可预测要求，并避免随机数失败触发 rustls 发送层 unwrap。AES 扩展密钥、原 MAC key 和 IV 派生输出有清零处理；上游 HMAC 内部临时哈希状态未承诺全部清零。

静态 RSA 客户端允许没有 ServerKeyExchange 的握手，先验证证书链/主机名/既有 pin，再检查 rsaEncryption + NULL、公钥范围和 KeyUsage 的 keyEncipherment。公钥 DER 解码在分配大整数前限制长度，显式支持 2048..8192 位，修正上游 RSA 默认构造函数只允许 4096 位的限制；六种 PKCS#1/PSS SHA-256/384/512 签名验证也使用这一范围。每次产生 48 字节随机 premaster，写入 TLS1.2 版本并使用 PKCS#1 v1.5 公钥加密。EMS、客户端认证、Finished、恢复和关闭沿真实 TLS 状态机运行；未增加服务端 RSA 私钥解密，也不将 RSA 当成 ECDHE。

密码测试中，连接级篡改覆盖四 CBC 套件 × 双方向 × IV/首块/尾块，确认坏记录后的同序号正确记录也不能继续输出明文。独立 Go 对端覆盖所有八套件、碎片和最大记录、CertificateStatus 消息、客户端证书、恢复及正常关闭；静态 RSA 同时验证拒绝仅 digitalSignature 的证书。CertificateStatus 用例仅验证 stapled OCSP 消息的握手顺序，默认 WebPki verifier 不做 OCSP 吊销判断，不能把它计作吊销验证。

RSA premaster/padding 和 RSA/P-256/P-384/P-521 签名前，先用可失败的系统随机数调用获取 32 字节 seed，再由局部 ChaCha20 CSPRNG 供给上游的 infallible RNG 接口。系统熵源失败返回 FailedToGetRandomBytes，不在 PKCS#1 padding、PSS salt 或 ECDSA nonce 路径触发 panic。RSA 私钥操作启用 blinding，仍保留上游的签名方案优先级和 wire 编码。seed/premaster 缓冲释放时清零；rand_chacha 0.3 内部状态没有完整擦除保证。

最终 42 项密码测试通过，包含 Go 8192 位证书及六种签名向量、TLS1.2/1.3 双向认证，以及静态 RSA 的错误 Finished、提前业务数据、意外 ServerKeyExchange。错误 Finished 测试使用认证有效的 CBC/GCM record，确认进入 Finished 校验后拒绝错误 verify_data；认证失败后的连接永久关闭业务输出。三组独立 Go 网络矩阵另行运行且全部通过，包括 8192 位 RSA 的六个静态 RSA/ECDHE 套件及恢复。Clippy 默认检查通过但保留代码风格提示，`-D warnings` 检查未通过，不将其报告为零警告。

CBC 的恒定工作量验证路径优先保证可审查性，额外哈希开销明显；它只在显式选择时启用。本轮封存基线不含 TLS1.0/1.1、完整浏览器 ClientHello 模板与 ALPS；后续 ALPS 实现单独记录在 [浏览器 TLS 基础](browser-tls-foundations.md)，不能将这些套件互通等同于 uTLS 指纹完成。

## Naive

Android 转换默认 H2 连接窗口 128 MiB、流窗口 64 MiB；指定 `stream_receive_window=W` 时转换为连接 W、流 floor(W/2)。H3 默认流窗口 6 MiB、连接窗口 15 MiB，两字段独立；QUIC 不再把流窗口静默缩小到连接窗口。零表示采用默认值，原生 JSON 的 256 KiB 默认不变。2026-11-26 整合修正：Naive 的 KB/MB/GB 按 1024 进制解析；取消内部 64/128 MiB 上限，采用固定 Cronet 入口实际生效的 31 位范围。并发缓存按需创建，可保留超过 16 路的配置，不按配置预分配连接。

H2 初始连接信用为协议规定的 65535 字节，小窗口目标在消费后生效；h2 库会合并很小的 WINDOW_UPDATE 增量。测试读取实际 SETTINGS 与连接信用，而非仅检查配置结构。H3 由独立 Go 对端读取真实 TLS transport parameters，覆盖流窗口大于连接窗口的合法配置。窗口语义修复不等于 Chromium TLS/H2/H3 指纹等价。

## TCP Brutal

smux/yamux/h2mux 在首业务流前通过 `_BrutalBwExchange:0` 交换带宽。Mbps 使用 checked multiplication 转为 B/s，验证最低速率、状态字节、截断与有界错误长度；远端拒绝、超时或取消不会把失败 session 放进池。Brutal 每条线路只使用一个 carrier，保留本地 128 并发流上限，并与网络代际一起退休。

只有拥有独立 TCP 载体的流提供设置 socket 选项的能力；该句柄不提供 I/O，TLS/SS/VMess/VLESS/WebSocket 一对一包装可以传递，QUIC/H2/嵌套 mux 不提供虚假的 TCP 能力。实际设置 `TCP_CONGESTION=brutal` 和选项 23301，ABI 参数按目标布局构造并初始化填充字节；参数失败时恢复原算法，恢复失败则关闭连接。

按固定上游行为，本地内核模块不存在时记录 debug 并继续已成功的远端协商；不能声称本地加速已经启用。服务器完成答复后可以立即关闭首控制流，客户端在完整成功答复后将本端关闭错误作为清理诊断。真正的内核拥塞控制效果仍需加载 tcp-brutal 模块的环境验证。

配置与基础内核共 64 项测试通过。最终 RSA 修正后的内核快照 2860/2860 通过，36 项外部环境测试默认忽略；其中 16 项独立 Go 互通另行运行全部通过，包含三种 mux × padding 的 Brutal TCP/UDP、拒绝及连接复用，以及 Naive H3 的实际 transport parameters。

四 ABI 开发 AAR 已完成，活动依赖和 ELF 动态依赖审计均未发现禁止的 C/C++ 密码库或额外非系统动态库。AAR SHA256 为 `456af2a96ed6ba9800c286a198f61cf14412b792df5af7648a1be1a3839bc69b`，使用 Cargo dev，不是优化 release。2,810 个源码/fixture/构建输入的哈希确认构建期间未改变，见 `target/android/legacy-brutal/source-files.json`；测试与构建日志见同目录 `validation.json` 和 `evidence/`。

2026-11-21 已完成 App 验证并归档至 `target/android/app-legacy-brutal/`：四个 Debug APK、四个 unsigned Release APK、138 项 JVM 测试（30 suites）全通过，Release 的 R8、资源压缩与 lintVital 通过。每个 APK 的 libaerobox.so 都与封存 AAR 经同一 NDK strip 操作后的字节一致，四个 Release 的 DEX 保留 14 个 JNI 入口和接口/两个实现中的 8 个平台回调；未打包 libbox/Cronet。Debug 签名验证通过，Release 确认未签名。完整 lintRelease、优化原生 release 与真机运行不在这次通过范围内。

同日后续完成同一份 2,810 文件快照的 **Rust 优化 release** 四 ABI 构建，输入哈希再次一致。
AAR 大小 51,651,833 字节，SHA256 为
`4346f67fa2b12f019ea349d333359d476eda2f227cc057961b013a6bc51002ab`；
使用 opt-level=3、thin LTO、codegen-units=1。优化密码测试 42 项及三组独立 Go 矩阵也通过。
安装包重新从该封存 AAR 构建，八个 APK、138 项 JVM 测试及上述 JNI/DEX/ELF/签名审计再次通过，
见 `target/android/app-legacy-brutal-release/manifest.json` 和 `evidence/`。
旧开发版 AAR/八个 APK 已删除以回收空间，原验证记录及 `superseded.json` 保留。
后续 ALPS/多 share 代码不在这份优化基线中，不能用这份 APK 证明后续源码已打包；仍无真机验收。
