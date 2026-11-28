# Android 的 Firefox120 TLS 指纹

2026-11-25：Firefox120 已完成主机验证并合入 Android 内核，四 ABI 优化 AAR 与八个 APK 已封存。
最终清单为 `target/android/app-firefox-release/manifest.json`；设备尚未连接，真机 VPN 验收仍待进行。
本轮包含真实 FFDHE、记录大小限制、委托凭据、普通 TLS 和 REALITY 生产入口。

本项目只实现 Android 内核。`firefox` 是原 Android 配置中的 TLS 指纹选项，目标为 App 固定使用的
MetaCubeX/uTLS v1.8.7 `HelloFirefox_120`。它不是 Firefox 浏览器客户端，也不代表当前 Firefox 的完整网络行为。
现有 `safari`、`ios` 同样是 Android 节点的指纹名称，没有新增 iOS 客户端或 Apple 平台目标。

## 配置与范围

转换器将 Android `tls.utls.fingerprint: "firefox"` 映射为原生 `firefox120`。
下面只是节点内的 TLS 配置片段，需要配合完整的 VMess、VLESS 或 Trojan 节点；当前发布包是否支持，以其封存清单为准。

```json
{
  "tls": {
    "enabled": true,
    "server_name": "proxy.example",
    "utls": {
      "enabled": true,
      "fingerprint": "firefox"
    }
  }
}
```

| 连接路径 | 实际允许的 TLS 版本 | 服务器认证与委托凭据 |
| --- | --- | --- |
| Firefox 普通流 TLS | 1.2、1.3 | 保留原证书链、主机名和配置的 SPKI pin；TLS1.3 可以验证 DC |
| Firefox + VLESS Vision 普通 TLS | 仅 1.3 | 保留相同证书策略和 DC 验证 |
| Firefox + REALITY，含 Vision | 仅 1.3 | 保留 REALITY 原有 HMAC、可选 ML-DSA 及 Ed25519 认证；不接受服务器 DC |

REALITY/Vision 的 ClientHello 保留固定模板的兼容字段，实际版本选择仍受 TLS1.3 策略限制。
REALITY 的 DC 扩展只是该模板的广告字段，不改变其认证方式；也不会将 Firefox 偷换为 Chrome。
普通 TLS 的默认配置与其他指纹不会自动开启 DC、记录大小协商或 FFDHE。

真实 ECH、QUIC/Naive 浏览器模板组合以及冲突的显式版本、密码套件、曲线配置明确拒绝。
模板中的 ECH GREASE 不会提供真实 ECH 隐私。`random`、`randomized`、`360` 等尚未实现的选项不通过 Firefox 别名放行。
REALITY 不支持显式 `curve_preferences`，转换器直接拒绝该字段。

显式提供密码套件或曲线时，必须与模板完整列表及顺序一致；不能用子集继续保留原指纹标签。
普通 Firefox 的显式版本边界为 1.2–1.3；Vision/REALITY 在对应传输内部另行限制到 TLS1.3。
原生 REALITY 的显式 TLS1.3 套件顺序为 AES-128-GCM、ChaCha20-Poly1305、AES-256-GCM。

## 实际握手能力

Firefox 提供 17 个密码套件：3 个 TLS1.3 套件和 14 个 TLS1.2 套件。TLS1.3 顺序为
`1301,1303,1302`；TLS1.2 包含对应的 ECDHE/RSA、ECDHE/ECDSA、AES-GCM、ChaCha20-Poly1305、
AES-CBC 和静态 RSA 实现。此指纹不启用 TLS1.0、TLS1.1、3DES、RC4 或 DSA。

组列表为 X25519、P256、P384、P521、FFDHE2048、FFDHE3072。首次发送独立生成的 X25519 和 P256
两个真实 key share；普通 TLS 可通过 HRR 选择其余支持的组。仅 cookie 的 HRR 保留原份额，换组 HRR
只发送指定的新份额。REALITY 保留独立的 P256 份额，同时使用 X25519 生成其认证材料；REALITY 不接受 HRR。
FFDHE 仅用于 TLS1.3，不宣称实现 Firefox 未广告的其他有限域组或 TLS1.2 DHE 套件。

保留模板 11 项握手签名算法的顺序。SHA1 仅属于显式旧 TLS1.2 握手的兼容映射，不加入 X.509
信任链验证算法集合；TLS1.3 选用 SHA1 始终拒绝。普通 Firefox TLS1.3 不能接受未广告的 Ed25519
CertificateVerify；REALITY 的原证书 Ed25519 例外只在其认证路径有效。

Firefox 不发送 ALPS 或证书压缩广告，不能套用 Safari 的 zlib 或 Chrome 的 Brotli 行为。
保留 ALPN 配置和默认 h2/http1.1，普通 TLS1.2 支持已有的一次安全重协商，检查 Finished 绑定、
证书、ALPN、EMS 与版本连续性。固定模板的完整首包、HRR 及重协商分别验证，不将抓包后 EOF 算作认证成功。

## 记录大小与委托凭据

RFC8449 的 `record_size_limit` 广告为 16385，表示 TLS1.3 完整接收容量，包含内部内容类型与 padding。
对端协商较小上限时，发送握手、应用、告警和 KeyUpdate 都遵守该上限；不只裁剪应用层 write。
该设置不等同于允许任意小的接收缓冲，且与 `max_fragment_size` 独立。未协商时维持对应版本的原记录规则。

Firefox 开启 RFC9345 服务器委托凭据验证后，每次连接完整认证：不恢复已有票据、不保存新的 TLS1.3 票据、
不发送 early data。服务器可以不发送 DC，转而使用原证书完成普通 CertificateVerify；此时仍不恢复会话。

收到 DC 时，先按现有应用策略验证原证书链、主机名和 SPKI pin，再验证委托资格、时间、发行者签名和被委托密钥。
pin 始终绑定原证书的 SubjectPublicKeyInfo，不改为被委托公钥。显式关闭原证书校验的配置仍遵循其既有语义，
DC 包装不会把一个不安全的内层 verifier 变成强证书校验。

委托证书必须包含唯一、非关键且编码正确的 DelegationUsage，并允许 digitalSignature。
DC 剩余有效期最多 7 天，结束时间必须严格早于原证书到期时间。签名绑定完整原证书、服务器角色、Credential
内容和签名算法；所选算法必须对应实际发出的主签名列表与 DC 列表，HRR 后使用最终 ClientHello 的实际广告。
拒绝未广告、非叶子、重复、错误消息位置、越界编码及 TLS1.3 SHA1 DC/CV。

Firefox 固定 DC 广告支持 P256/SHA256、P384/SHA384、P521/SHA512，保留上游的 ECDSA/SHA1 广告值但不允许选用。
底层 DC API 可显式选择 Ed25519；该能力不会扩展固定 Firefox 模板的广告。
发行者签名目前支持对应曲线的强 ECDSA、RSA-PSS-rsae 和显式广告的 Ed25519。
正确但采用 RSA-PKCS1 或跨曲线 ECDSA 的发行者签名也会拒绝；这是当前保守的互操作边界，不宣称是 RFC9345 唯一允许的集合。
被委托密钥不接受 rsaEncryption RSA 形式。

REALITY 无论 DC 内容是否有效都拒绝实际 DC 条目。其原证书必须通过连接专属 HMAC 等原有认证，
之后再验证同一证书公钥的 Ed25519 握手签名；普通 TLS 不能使用这个例外。

## 纯 Rust 与资源边界

自有内核工程使用 Rust2024；vendored 库保留各自 edition，避免无关重写。
TLS、签名、AEAD、密钥交换和新增 FFDHE 的产品实现使用 Rust/RustCrypto，不引入 OpenSSL、ring、AWS-LC
或其他 C/C++ 密码后端。Go 对端与 OpenSSL fixture 生成器仅供独立验证，不进入 Android 内核。

FFDHE 使用 RFC7919 固定组与 `crypto-bigint` Montgomery 运算，秘密指数分别为固定 256/384 位，
按固定迭代次数执行平方、乘法和常数时间选择，不用变量时间 BigUint 对秘密指数求幂。
对端份额长度和数值范围严格验证。受控的私钥和工作值使用零化包装；不承诺编译器、寄存器及算法内部所有临时副本均可擦除，
也不将这些实现选择称为已完成独立密码安全审计。
编译和验证由同一受限队列串行执行；源码开发与只读审查使用一个主代理和一个子代理。

## 验证状态

以下是 2026-11-25 文档候选生成时读取到的分阶段证据，均来自隔离树，不能当作最终产品验收：

| 范围 | 已记录的阶段结果 | 证据位置 |
| --- | --- | --- |
| FFDHE | 开发/发布各 7 个原语、5 个握手、2 个独立互通测试 | `target/firefox-ffdhe-validation-stage/status.json` |
| DC 核心 | 开发/发布各 13 个密码测试、5 个内部 harness 测试 | `target/firefox-delegated-validation-stage/status.json` |
| RSL | 开发/发布各 9 个配置/真实互通测试；其组合密码回归各 199 项 | `target/firefox-record-size-stage/live-status.json` |
| Firefox 模板 | 开发/发布各 10 项；各 10 个完整首包、50 个 HRR 场景（100 个 ClientHello）精确对照 | `target/firefox-profile-stage/rust-status.json`、`evidence/*wire-comparison.json` |
| 独立 DC 对端 | 开发/发布各 3 项入口测试，覆盖各 47 个成功连接、52 个拒绝连接 | `target/firefox-delegated-live-stage/status.json` |

DC 首轮因测试误判 WebPKI 的未知关键扩展错误而停止；修正只涉及该具体错误分类和不支持等值比较的
opaque error 持续失败断言。第二轮已经通过上述独立矩阵，运行时认证策略未因此放宽。

最终合并快照通过密码开发/发布各 225 项、生产浏览器入口
17 项、内核 2876 项、Quinn 409 项、
Android 主机 43 项、配置 42 项和独立 Go 协议互通
18 项。密码测试无忽略；内核完整回归默认忽略 49 项外部环境测试，
本轮相关互通已单独显式执行。内核首轮两项旧夹具因后台服务缺少登录环境而失败，
修复 systemd 登录环境后在同一可执行文件上两项通过；完整原始记录和重跑来源保留在
`target/firefox-production-stage/resume-v2.json`。没有为此修改产品源码。

生产 DC 验证包含 60 组完整连接和 18 组拒绝场景，保留原证书 SPKI pin；
另验证 REALITY 拒绝实际 DC 条目、普通 Firefox 拒绝未广告 Ed25519，以及六种交换组。
Firefox 首次/HRR 完整报文与旧 Android、Edge/QQ 报文比较在开发和发布两种模式均通过。
armv7 源码检查与四 ABI 纯 Rust 依赖审计通过。

四 ABI 优化 AAR 和八个 APK 已经过 138 项 JVM 测试、Debug、
未签名 Release/R8/资源压缩/lintVital 和 JNI/DEX 核对。64 位 ELF LOAD 对齐为 16 KiB。
构建采用 opt-level=3、thin LTO，shoes 代码生成单元为 16、其余为 1，继续限制构建内存。
封存 AAR SHA256：`b7c0f26982740250fe7634df41e27092db2953a21970ab978ffa7caa02f75691`。
冻结输入 SHA256：`a2ad19eb07e3901fbd5f105ec14d59b30245f9e3cf6fbc6a3017e61357d0c4ed`。
完整结果见 `target/firefox-production-stage/validation.json` 和
`target/android/firefox/status.json`。尚未安装、发布或完成真机网络测试。

规范依据：[RFC7919](https://www.rfc-editor.org/rfc/rfc7919)、
[RFC8446](https://www.rfc-editor.org/rfc/rfc8446)、[RFC8449](https://www.rfc-editor.org/rfc/rfc8449)、
[RFC9345](https://www.rfc-editor.org/rfc/rfc9345)。已有指纹与剩余工作见
[Android 浏览器指纹](android-browser-integration.md)和[剩余协议工作](remaining-protocol-work.md)。
