# Android 360 指纹

Android `tls.utls.enabled=true, fingerprint="360"` 对应原生 `360_7_5`，
复现固定 sing-box v1.14.4 / uTLS v1.8.7 的 360 7.5 ClientHello。
这是 Android 内核的网络指纹选项，没有新增其他平台客户端。

模板使用 TLS1.0–1.2、P256/P384/P521、32 字节 session ID 和原始扩展顺序。
默认 ALPN 为 spdy/2、spdy/3、spdy/3.1、http/1.1，支持既有显式 ALPN 覆盖；
广告这些名称本身不代表实现了 SPDY 应用协议。模板没有 EMS、padding、GREASE、
ECH、TLS1.3 key share、证书压缩、ALPS、DC 或记录大小扩展。

线上的 20 个套件编号中，13 个有实际实现：ECDHE-ECDSA/ECDHE-RSA 的 AES-CBC、
SHA256-CBC、RC4，以及静态 RSA 的 AES-CBC/SHA256-CBC、3DES、RC4。
原模板的六个假占位和默认禁用的 003d 只保留原始广告，服务器选择它们会明确失败。
三项 SHA256-CBC 只支持 TLS1.2，其他十项实际覆盖 TLS1.0/1.1。
这些旧算法只进入显式模板，普通 TLS 默认提供者没有被放宽。

新增 RC4 记录层完全使用 RustCrypto，分别维护每方向、每密钥 epoch 的连续流状态、
HMAC-SHA1 和严格记录序号；认证/顺序错误后永久失败并清理状态。
TLS1.0 的 1/n-1 拆分仅对实际 RC4 写密钥关闭，CBC 继续拆分。切换策略随新写密钥
在 ChangeCipherSpec 生效，避免重协商时影响仍在使用的旧密钥。

真实服务器签名能力为六项，实际广告另有两个历史 DSA 占位。
TLS1.2 ServerKeyExchange 按最终发出的签名列表检查；TLS1.0/1.1 使用其协议定义
的旧签名路径。证书链、名称和 pin 保持正常验证。客户端证书签名服从独立的
CertificateRequest，已用仅要求 P521/SHA512 的真实请求检查这一边界。

安全重协商绑定两端上一轮 Finished，保留原始布局并重新认证；非 EMS exporter
继续拒绝。NPN/旧 ChannelID 只有原模板的空广告，服务端选择会明确拒绝。
REALITY、Vision/TLS1.3-only、QUIC、ECH、Naive 与此模板不兼容。

独立 Go 对端验证 99 次成功连接、66 次证书拒绝以及全部真实旧套件/版本组合；
首次完整报文与固定 uTLS 比对。重协商、RC4/CBC epoch 切换、分片和错误状态有独立
验证，记录分别在 `target/browser360-production-stage/`、
`target/rc4-live-validation-stage/`。最终合并回归采用 randomized 的同一源码快照，
不是将两个分别通过的产品版本直接拼接交付。

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

