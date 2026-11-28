# Android 11 与 Chrome 133：固定版本 ClientHello 实证

本审计以原 Android 提交 `7206146effd0ac3602eb5b96ad5986e5af5ced5e` 固定的
sing-box `v1.14.4`、MetaCubeX/uTLS `v1.8.7` 为准。2026-11-20 的独立 Go 捕获工具和
原始/归一化结果保存在
[`tests/fixtures/utls-reference`](../crates/aerobox-crypto/tests/fixtures/utls-reference/README.md)。
工具锁定正式模块及 `go.sum`，不使用绝对路径 replace，也不进入 Rust/AAR 依赖图。

28 份 ClientHello 捕获证明实际写出的结构；其中捕获 socket 随后返回 EOF，不表示握手成功。
另有 16 次 uTLS 客户端与 Go 标准 TLS 服务端的真实内存管道握手、双向 echo，验证下面的旧版
TLS、配置覆盖、客户端证书和会话恢复结论。当前 Rust CBC/静态 RSA 基础已单独实现并通过密码
及独立 Go 测试；后续 RSA 修正后的完整内核回归 2,860 项通过，四 ABI 开发 AAR 已完成。
具体范围见 [本轮验收](legacy-tls-naive-brutal.md)。这是固定上游的历史线协议审计；
2026-11-23 的 Rust Android11 实现与实际执行结果另见 [Android11 接入](android11-integration.md)。

## Android 11 默认报文

模板是 [`HelloAndroid_11_OkHttp`](https://github.com/MetaCubeX/utls/blob/v1.8.7/u_parrots.go#L1742)。
以 SNI `android11.example` 为例，首个 TLS record 总长 192 字节：类型 22，record version
`0x0301`，payload 187 字节；ClientHello type=1，body 183 字节，legacy_version=`0x0303`。
client_random 和 session_id 各 32 个随机字节，compression_methods 仅 `00`。
无 GREASE、无 padding extension、无 key_share、无 supported_versions、无 ALPN。

12 个 cipher 的顺序必须保留：

| 顺序 | 编号 | 套件 |
| --- | --- | --- |
| 1 | c02b | ECDHE_ECDSA_AES_128_GCM_SHA256 |
| 2 | c02c | ECDHE_ECDSA_AES_256_GCM_SHA384 |
| 3 | cca9 | ECDHE_ECDSA_CHACHA20_POLY1305_SHA256 |
| 4 | c02f | ECDHE_RSA_AES_128_GCM_SHA256 |
| 5 | c030 | ECDHE_RSA_AES_256_GCM_SHA384 |
| 6 | cca8 | ECDHE_RSA_CHACHA20_POLY1305_SHA256 |
| 7 | c013 | ECDHE_RSA_AES_128_CBC_SHA |
| 8 | c014 | ECDHE_RSA_AES_256_CBC_SHA |
| 9 | 009c | RSA_AES_128_GCM_SHA256 |
| 10 | 009d | RSA_AES_256_GCM_SHA384 |
| 11 | 002f | RSA_AES_128_CBC_SHA |
| 12 | 0035 | RSA_AES_256_CBC_SHA |

扩展顺序固定为 `[0, 23, 65281, 10, 11, 5, 13]`，以下是 extension body，不含 type/length：

| 编号 | 内容 |
| --- | --- |
| 0 SNI | `0014 00 0011` 后接 ASCII `android11.example`；空名/数字 IP 时整个扩展省略 |
| 23 EMS | 空 |
| ff01 renegotiation_info | `00`；模板内部 `Renegotiation=RenegotiateNever`，并非允许重协商 |
| 10 supported_groups | `0006 001d 0017 0018`：X25519、P-256、P-384 |
| 11 ec_point_formats | `01 00`：uncompressed |
| 5 status_request | `01 0000 0000`：OCSP，空 responder list/extensions |
| 13 signature_algorithms | `0012 0403 0804 0401 0503 0805 0501 0806 0601 0201` |

签名顺序是 ECDSA-P256-SHA256、RSA-PSS-SHA256、RSA-PKCS1-SHA256、ECDSA-P384-SHA384、
RSA-PSS-SHA384、RSA-PKCS1-SHA384、RSA-PSS-SHA512、RSA-PKCS1-SHA512、RSA-PKCS1-SHA1。
不要加入 Ed25519、ECDSA-P521 或额外签名后仍称完全匹配。

record version 来自 [`conn.go`](https://github.com/MetaCubeX/utls/blob/v1.8.7/conn.go#L1050)
首个 ClientHello 的兼容处理；随机 32 字节 session_id 来自
[`ApplyPreset`](https://github.com/MetaCubeX/utls/blob/v1.8.7/u_parrots.go#L2829)，不是恢复会话的证据。

## 旧 TLS 与配置覆盖：已真实握手确认

Android 模板的 `TLSVersMin/Max` 均为零，又无 supported_versions。
[`SetTLSVers`](https://github.com/MetaCubeX/utls/blob/v1.8.7/u_conn.go#L694)
将范围设为 TLS **1.0–1.2**，并覆盖原 Config.MinVersion/MaxVersion。
独立对端强制 TLS1.0、TLS1.1、TLS1.2 均握手和 echo 成功；将客户端 min=max=TLS1.3 后，
对端仍成功选中 TLS1.0 + `c013`。因此“Android11 是纯 TLS1.2 模板”的旧描述不正确。

| Android/sing-box 字段 | 固定版本实际行为与证据 |
| --- | --- |
| min_version / max_version | 先解析，非 ECH 路径随后被模板改成 1.0–1.2；已测 1.1-only、1.2-only、1.3-only 输入 |
| cipher_suites | `newUTLSClient` 先在 Go `tls.CipherSuites()` 中查名，未知名字仍早失败；有效 Config 列表随后不限制 preset。已仅配置 c02f，而服务端成功选 c02b |
| curve_preferences | sing-box 的 uTLS constructor 没有读取该选项；即直接给 uTLS Config 设置 P-521-only，也被 SupportedCurvesExtension 改成 29/23/24，实测 X25519 成功 |
| alpn | sing-box wrapper 只替换已存在的 ALPN 扩展；Android 模板没有这个扩展，所以 h2/http1.1/custom 都不上 wire。SetNextProtos([h2]) 会先补 http/1.1，但仍不会新增扩展 |
| disable_sni | 省略 SNI；正常校验通过 `InsecureServerNameToVerify` 保留独立校验名。数字 IP 同样省略 SNI |
| certificate / pin / insecure | 是认证策略，不应由报文模板覆盖；固定版 pin 路径会设置 InsecureSkipVerify=true 并单独核验公钥，不等同于根 CA 验证再 pin |
| client_certificate / key | 成对解析并安装，实测 TLS1.2 mTLS 服务端收到一个客户端证书；不会因此改变 ClientHello 扩展集合 |
| resumption | sing-box 默认没有配置 ClientSessionCache；Android 模板也无 ticket/PSK 扩展。即额外显式提供缓存，两次 TLS1.2 握手仍均 DidResume=false |

覆盖逻辑见 [`utls_client.go`](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/tls/utls_client.go#L168)、
[`ApplyPreset`](https://github.com/MetaCubeX/utls/blob/v1.8.7/u_parrots.go#L2820)、
[`SupportedCurvesExtension`](https://github.com/MetaCubeX/utls/blob/v1.8.7/u_tls_extensions.go#L332)、
[`sessionController`](https://github.com/MetaCubeX/utls/blob/v1.8.7/u_session_controller.go#L79)。
Rust 迁移不能悄悄丢掉用户显式安全限制以模仿上游覆盖；在精确 profile 与显式配置相冲突时，
应明确报错或明确采用经过验证的可配置模式，不能两者都声称满足。

当前 Rust TLS1.2 CBC/静态 RSA 不等于 TLS1.0/1.1 支持。后两者还需旧 PRF、隐式 CBC IV
及记录拆分、MD5+SHA1/RSA 和旧签名、握手版本与降级检查的完整实现。若先交付 Android11
的 TLS1.2 子集，必须在命名和文档中清楚标注，不能称完整兼容。

## Android11 与 REALITY / ECH

REALITY 固定实现需要 ClientHello 阶段已有 X25519 私钥；Android11 无 key_share，
`State13.KeyShareKeys.Ecdhe` 为空。
[`reality_client.go:199`](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/tls/reality_client.go#L199)
返回 `nil ecdheKey`，不能把这个原本不可用的组合静默改成 Chrome。
REALITY+ECH 本身也被固定 sing-box 明确拒绝。

ECH 捕获暴露 v1.8.7 的错误路径：Android 模板不含实现 `EncryptedClientHelloExtension` 的
扩展，`computeAndUpdateOuterECHExtension` 返回缺失错误，但
[`MarshalClientHello:582`](https://github.com/MetaCubeX/utls/blob/v1.8.7/u_conn.go#L582)
没有处理该错误。实际写出的是改用 Go 默认序列化顺序的无效报文：SNI=public.test，
fe0d body=`01`（inner marker）、versions 仅1.3，却仍只有12个旧套件且没有 key_share。
这是 wire 捕获和源码证据，**不是成功 ECH 互通**。显式 ECH+max1.2 则在构建阶段失败。
Rust 应前置拒绝 Android11+ECH；现有正常 ECH accept/rotate/reject 安全语义不能被 profile 绕过。

## Chrome133：下一阶段可用基准

[`HelloChrome_133`](https://github.com/MetaCubeX/utls/blob/v1.8.7/u_parrots.go#L884)
的实际版本范围是 TLS1.2–1.3，无 TLS1.0/1.1 需求。当前已完成 CBC/静态 RSA 基础可覆盖其
所有真正可协商套件。后续 ALPS、多独立 key share 和受控 ClientHello 构造 API 已合入；
基础快照密码测试各65项、内核2,860项与16项协议互通通过；ECH/REALITY/重协商后续快照密码测试各75项、完整内核2,860项与16项互通也已通过。
2026-11-23已接入Android的Chrome别名，40项配置测试和6项生产专项通过，完整回归与Android更新继续执行；具体范围见 [Chrome133配置接入](chrome133-integration.md)。Android11及其他浏览器模板仍未开放。

2026-11-21 新增独立 [TLS profile 对端](../tests/reference/tls-profile-peer/README.md)。
它直接用 Go 密码原语构造 TLS1.3 服务端，后续已与标准 Go TLS/uTLS Chrome133 完成十五次
65,537 字节回显和 close_notify，覆盖 Brotli 证书、ALPS 17613/17513、空/非空双向设置、
X25519MLKEM768、P-256/P-384 和仅 cookie 的 HelloRetryRequest；
另五例确认错误SCT、解压长度和Finished被拒绝。客户端 EncryptedExtensions 进入实际 Finished
转录校验，因此不只是 ClientHello 广告检查。这仍是测试基础，不计作 Rust 指纹实现完成。

对端还证实固定 uTLS 的客户端设置查找错误：`u_handshake_client.go:158` 使用
`hs.serverHello.alpnProtocol`（TLS1.3 此字段为空），所以即显式配置
`ApplicationSettings["h2"]` 仍发空设置。测试另用空键验证非空设置与转录；该 workaround
不是 App 配置行为，后续 Rust 的协议实现应使用实际协商的 ALPN，不能照搬这个错误。

cipher 顺序：

```text
GREASE,1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035
```

record version=`0301`，ClientHello legacy_version=`0303`，random32、随机 session_id32、
compression=`00`。正常有18个扩展：GREASE 空扩展固定第一，另一个不同 GREASE 扩展（body `00`）
固定最后；中间16项每连接随机打乱。**此模板没有 padding 扩展21**。

| 扩展 | 精确内容或约束 |
| --- | --- |
| SNI / EMS / renegotiation_info / points / OCSP | 与上述结构相同；Chrome内部允许一次renegotiation，与Android的Never不同 |
| supported_groups 10 | GREASE、X25519MLKEM768=`11ec`、X25519=`001d`、P-256=`0017`、P-384=`0018` |
| signature_algorithms 13 | `0403,0804,0401,0503,0805,0501,0806,0601`；无SHA1 |
| session_ticket 35 / SCT 18 | 首次均空body |
| ALPN 16 | 默认 h2、http/1.1；sing-box显式ALPN替换这个已有扩展 |
| key_share 51 | GREASE/1字节00，11ec/1216字节（1184 MLKEM公钥+32 X25519），001d/32字节 |
| psk_key_exchange_modes 45 | `01 01`，即 psk_dhe_ke |
| supported_versions 43 | GREASE、TLS1.3、TLS1.2 |
| compress_certificate 27 | `02 0002`，只支持 Brotli |
| ALPS 17613 | `0003 02 6832`，仅 h2；换成自定义 ALPN 后此ALPS列表仍为h2 |
| GREASE ECH fe0d | outer=0，HKDF-SHA256/AES128GCM，随机config_id，32字节enc，payload长度144/176/208/240之一 |

最容易漏掉的结构差异：**hybrid 末尾的 X25519 公钥与单独 X25519 公钥不同**。
固定源码为两者分别生成密钥，捕获也验证 `hybrid_x25519_equals_standalone=false`。
当前 rustls hybrid component 复用策略不能直接声称相同指纹；profile 路径需要保存独立密钥，
并根据 ServerHello/HRR 所选 group 使用对应私钥。supported_groups 与 key_share 的 GREASE 值
相同；cipher/version/首尾extension 的 GREASE 各按其seed生成，不能强制全部相同。

后续 Rust API 已为普通 Chrome133 路径保留这两个独立私钥，并按实际 ServerHello/HRR
选择。上述默认 hybrid component 行为只适用于未指定独立 share 的默认 TLS 配置。

### REALITY 包装后的差异

2026-11-21 进一步固定 sing-box v1.14.4 到提交
`c005f35300ce76427dc285481ec5695f5b179cd2`。其
[`reality_client.go`](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/common/tls/reality_client.go#L139)
在模板生成后，从 supported_groups 和 key_share 中移除 X25519MLKEM768，再重新构造
ClientHello。因此该 Android REALITY 路径应为 GREASE/X25519 的 share，group 列表为
GREASE/X25519/P256/P384，不能直接拿普通 Chrome 的双 share 报文充当相同基准。
认证使用独立 X25519 私钥，session ID 内的客户端版本为 1.8.1。

该实现已合入，通用双 share REALITY API 也完成独立验证。Go 对端检查
session ID 的 AES-GCM、版本/时间/short ID，随后发送 HMAC 认证的 Ed25519 证书并执行
真实 CertificateVerify、Finished 和 echo。固定 uTLS 构造作为第二个客户端进行交叉
验证；生产认证桥接2项通过，但这些改动尚未计入旧CBC/RSA/Naive/Brutal AAR/APK。

Chrome的min/max/cipher/group非ECH覆盖行为与Android同类，但最终范围为1.2–1.3。
其支持ECH的扩展可被真实ECH替换；带 ECH 时上游不再按模板覆盖Config min/max，TLS1.2-only
仍失败。此前保存的真实ECH样本仅证明ClientHello构造；后续Chrome profile + ECH 已完成独立
accept/rotate/reject/badpublic、四种group、HRR和恢复矩阵，见浏览器TLS基础文档。
ECH私有inner布局尚未承诺与浏览器逐字节一致。

## 后续验收边界

先对 Chrome133 建立结构化比较，保留随机shuffle、GREASE关联、长度范围及独立公钥关系，
不要只比较 JA3/JA4。再强制逐套件/签名/group协商，完成TLS1.3 HRR、票据恢复、Brotli边界、
ALPS双方EncryptedExtensions、REALITY与ECH重试、两种fragment路径。未实现的可协商算法
不能仅作为指纹占位广告。Android11应等待旧TLS完整支持，或明确作为受限子集另行验收。

## TLS1.2 重协商实测

2026-11-21 固定 uTLS v1.8.7 的独立服务器补丁已与标准Go客户端及Chrome133完成90组
参考自测。Chrome133的第二个ClientHello保留前一次random、session ID、公开key share、
GREASE和扩展顺序，仅更新renegotiation_info的12字节绑定。实际TLS1.2 ECDHE重新交换
临时密钥。Rust按此保留一次有界的公开布局，收到新ServerHello仍禁止切换为TLS1.3。

Rust还验证了旧/新epoch的CCS加密、Finished绑定、客户端认证、证书和ALPN不变、
EMS降级拒绝，以及票据恢复后再做完整重协商。异步读写取消及短传输14组组合通过。
相关能力由`enable_tls12_renegotiation`显式启用，默认仍关闭；Android指纹配置接线另行验收。
参考对端、补丁哈希和命令位于[重协商测试](../tests/reference/tls12-renegotiation-peer/README.md)。
