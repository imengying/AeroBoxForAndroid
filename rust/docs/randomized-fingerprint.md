# Android randomized 指纹

本实现对应原 Android 固定的 sing-box v1.14.4 / MetaCubeX uTLS v1.8.7。
它是 Android 内核的 TLS 指纹选项，使用 Rust 2024 与 RustCrypto；独立 Go/Python
参考程序只参与验证，不进入 AAR。`randomized` 与五个固定模板中选一的 `random`
分别保存自己的进程状态。

`tls.utls.enabled=true, fingerprint="randomized"` 在首次使用时从系统熵生成一次
结构计划。Android 转换器和原生 TLS/REALITY 共用同一个 `aerobox-fingerprint`
实例。重连、配置检查失败、reload、核心 stop/start 都不会换种子；未启用 uTLS
不会触发选择。TLS random、session ID 和各条真实 key share 的私钥仍逐连接独立产生。

生成器复现 SHAKE256、Go Intn/Perm/Shuffle、浮点 coin、密码套件裁剪和
HKDF-SHA3-256 的 ALPS 分支。每个列表与生成工作量都有上限，没有公开的种子覆盖
或失败后重抽机制。2,048 个固定独立结构向量已在开发/优化模式逐字段比对。

普通 TLS 按实际计划支持 TLS 1.0–1.3，包括极罕见的 TLS1.2-only 分支；密码提供者
按实际顺序装入真正实现的 AES-GCM、ChaCha20-Poly1305、CBC、静态 RSA、3DES
和 RC4。TLS1.2-only 算法不会被用于旧版本。SHA1 只用于允许的旧握手，TLS1.3
CertificateVerify 与证书链算法不因此放宽，原有 CA、名称和 pin 检查继续生效。

ALPN、ALPS、EMS、OCSP、SCT 和安全重协商均服从实际发出的扩展。显式版本、
套件/曲线顺序与计划冲突时返回配置错误；计划没有 ALPN 而上层显式要求 ALPN 时
也会报错。服务器选择必须属于最终发出的 offer。TLS1.2 Client CertificateRequest
独立决定客户端签名算法，不错误地受 ClientHello 的服务器签名列表限制。
非 EMS exporter 继续拒绝；本模板不启用恢复或 0-RTT。

REALITY 先按固定上游规则移除 hybrid group/share，再校验结构；保留其 HMAC、
Ed25519 与认证前明文门控。支持实际首发的 X25519/P256 key share 以及计划包含的
TLS1.3 套件。REALITY 的 HRR 保持明确拒绝；普通 TLS 则支持真实组切换/混合组 HRR。
Vision/其他 TLS1.3-only 路径要求计划支持 TLS1.3。QUIC、真实 ECH 和 Naive 与此模板
的组合明确拒绝。

固定上游可能生成未列入 supported_groups 的 hybrid share。普通 TLS 对这样的
计划保持稳定错误，不私自改报文或重抽；REALITY 在上述移除步骤后可能仍可使用。
这项兼容边界必须与“随机模板每次都可用”区分。生成器极罕见的 TLS1.2-only 结果
也不能用于 REALITY/Vision。

验证记录按用途保留：生成器与固定上游捕获在
`target/randomized-generator-validation-stage/`、`target/randomized-reference-validation-stage/`；
1,068 条首次/HRR/配置/padding 对照在 `target/randomized-tls-stage/`。捕获中包括
预期拒绝，不能把捕获行数称为成功认证连接。实际互通验证包括独立 Go 的数据、
exporter、关闭、异常响应，Rust 对端的全部实际套件/组和客户端认证，以及原生
REALITY 工厂和异步流。最终统计以 `target/randomized-final-stage/` 和
`target/randomized-acceptance-stage/` 的已完成验证记录为准。

2026-11-26：360 与 randomized 已通过最终验收并合入主源码，random 也已进入本次安装包。
密码开发/优化各280项且无忽略，独立Go协议互通18项、Quinn409项、配置49项、
浏览器生产入口22项、Android主机48项通过。内核完整回归2,891项通过；其后仅修正
Vision测试夹具并增加REALITY测试，修正夹具与新增内容在同一最终可执行文件的
12项randomized专项中全部通过。最终产品语句与完整回归快照一致，继承关系和
测试差异在 `target/randomized-final-stage/host-inheritance.json` 明确记录。

四ABI优化AAR与八个APK已封存：`target/android/app-randomized-release/manifest.json`。
JVM 138项、Debug、未签名Release/R8/资源压缩/lintVital、JNI/DEX和
64位ELF的16KiB对齐检查通过。AAR SHA256：`ea9caa4778cb4190b707505ec4581185524d598d9ce6b3ac1e7154773cacedfb`。
实际Android设备尚未连接，未完成真机VPN、网络切换、分应用和后台资源验收。

