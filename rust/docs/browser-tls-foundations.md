# 浏览器 TLS 基础：ALPS、证书压缩与独立多 share

2026-11-21：以下改动经过 `target/browser-tls-stage/` 隔离验证后，已合入
`vendor/rustls`。2026-11-23的四ABI优化构建及八个APK已封存至
`target/android/app-chrome133-release/`，包含以下基础能力与Chrome133接线。基础快照的 2,860 项内核回归和 16 项独立协议互通已通过，记录在 `target/android/browser-wire/`。
Chrome133 的 Android 配置接线和生产模块验收已完成，见 [配置接入](chrome133-integration.md)；其他浏览器策略仍未开放。

## ALPS 实现

`ClientConfig.application_settings` 按 ALPN 名称预先配置固定设置，支持 17513、17613
两个编号。只在提供 TLS1.3 时广告，要求同时提供 ALPN。服务器选择的 ALPN 必须是
实际发送过且配置了设置的协议；两个编号同时返回、错误编号、没有 ALPN、在明文
ServerHello 返回 ALPS 都拒绝。空设置与没有协商 ALPS 保持区别。

收到服务器 EncryptedExtensions 后先保存待认证设置。只有证书、CertificateVerify、
Finished 及 ECH 接受检查通过后，`peer_application_settings()` 才公开新设置。
客户端 EncryptedExtensions 位于服务器 Finished 之后、客户端 Certificate/CertificateVerify/
Finished 之前，并纳入转录。应用流量密钥仍使用服务器 Finished 处的哈希；客户端签名、
Finished 和恢复主密钥包含客户端设置。

会话票据保存 ALPN、ALPS 编号、双方设置。0-RTT 只能使用与票据一致的本地设置；
配置变化会禁用该次早期数据，仍可完成正常会话恢复。服务器接受早期数据时不能再次
发送 ALPS，连接沿用票据设置；拒绝早期数据时重新交换并认证设置。HRR 清除早期数据
关联的设置。恢复前可读取来自已认证旧会话的设置，不会提前公开本次新响应。

协议依据：[ALPS 草案](https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps-01)。
固定 uTLS 的空 ALPN 查找错误没有照搬；Rust 使用实际协商协议选择设置。

## 长度和压缩边界

本地 ALPN 名称必须非空、唯一且不超过 255 字节，设置最多 65,531 字节。
ClientHello 的完整扩展列表、ECH 内外 ClientHello 及 ECH 扩展均在序列化前检查
u16 长度范围，避免调试 panic 或优化构建长度截断。握手重组只为 EncryptedExtensions
额外允许两个字节的向量长度字段，其他握手消息的原有 65,535 字节上限保留。
接收缓冲允许一个最大握手加一个承载记录，始终有上限。

已有 rustls Brotli 编解码使用 Rust 实现；测试通过 dev-dependency 开启 Brotli，
产品默认 TLS 没有因此增加证书压缩广告。实际 profile 接线时再显式选择解压器。
测试覆盖跨 TLS 记录的最大设置、过大声明、压缩长度不符和压缩数据尾随垃圾。

## 独立 key share

`ClientConfig.initial_key_share_groups` 指定初始 TLS1.3 share 的顺序，最多八个已启用、
唯一的 group。每个 share 独立生成和保存私钥；混合 X25519MLKEM768 与单独 X25519
不共享其 X25519 私钥。服务端选择任一个已发送 share 时使用对应私钥，并准确报告
协商 group。要求新 group 的 HRR 丢弃全部旧 share；仅要求 cookie 的 HRR 保留原 share。
服务端要求已提供 group 的 HRR 被拒绝。默认空列表保留原 provider/cache 行为。

后续 REALITY 验证已允许独立 X25519 认证，通用 API 可提供混合/独立 X25519 两个 share。
固定 Android 的 REALITY wrapper 会移除混合 share，Chrome133 策略单独按它处理；
REALITY 仍拒绝 ECH、HRR、0-RTT 与会话恢复。

## 独立验证

参考对端为 [tests/reference/tls-profile-peer](../tests/reference/tls-profile-peer/README.md)，
直接用 Go 原语实现有界 TLS1.3 服务端，不链接进内核。其完整握手先由标准 Go 和
固定 uTLS Chrome133 自测；票据/PSK binder、恢复和客户端证书由标准 Go 与增加显式
PSK 扩展的 Chrome133 模板分别验证。

Rust 矩阵覆盖两个 ALPS 编号、X25519/P256/P384、Brotli 开关、非空双方设置、mTLS、
拒绝协商、错误 Finished/压缩/ALPN/编号、最大设置、ECH 长度、0-RTT 接受/拒绝、
客户端设置变化、服务端设置轮换。多 share 矩阵由独立对端核对公钥不复用及发送顺序，
逐个选择 X25519/P256/P384/X25519MLKEM768，并验证新 group HRR、cookie HRR 和无效 HRR。

ALPS 独立快照优化测试 51 项通过；加入多 share 后普通和优化模式共 54 项通过，
内核编译检查通过，另行补充的多 share 恢复/HRR 矩阵也通过。标准 Go 的恢复+HRR
成功，固定 uTLS 对该组合明确报错，参考测试将此限制单独记录。
基础快照全量内核回归已经通过，后续ECH/REALITY/重协商快照也已完成回归，见文末续验记录。
Chrome配置接线的完整回归与四ABI/App更新已完成；真机VPN验收仍缺设备。

## ClientHello 构造策略

后续 `ClientConfig.client_hello_layout=Chrome133` 作为 TLS 库构造 API 已合入，
Android `fingerprint=chrome` 已接入并通过当前主机/四ABI验收。配置必须实际具备全部 15 个可协商套件、四种
密钥交换、指定的八种签名、Brotli、ALPS 17613 和两个独立初始 share；缺失能力报错。
不把无法协商的算法作为占位广告。构造发生在转录哈希和 PSK binder 计算前。

初始报文包含 16 个 cipher（含 GREASE）、正常 18 个 extension、五类独立 GREASE
选择、固定首尾 GREASE 与随机中间排列、X25519MLKEM768/独立 X25519 公钥及有界
GREASE ECH。首尾 GREASE 不同，supported_groups 与 key_share 共用 GREASE 值。
没有新增 padding。HRR 保持随机数、session ID、扩展次序和 GREASE ECH；新 group
替换旧 share，仅 cookie 的 HRR 保留公钥。PSK 扩展始终最后，未广告 group/signature
不能被服务端选中。

SCT 扩展新增严格非空、有界列表解析，支持 TLS1.2 ServerHello 与 TLS1.3 Certificate。
这里接收不透明时间戳并由握手转录认证；没有增加 CT 日志信任或证书透明度策略验证，
不能把 SCT framing 测试当成浏览器证书透明度政策已实现。

基础主源码调试与优化构建各 65 项密码/互通测试、2,860 项内核回归和 16 项协议互通通过。
随后 ECH/REALITY 快照各 69 项及生产认证桥接 2 项通过，已经合入。
2026-11-21 主机重启中断的旧验证单独标记，不计为通过。

该策略仍拒绝 QUIC；Android Chrome 配置接线的状态见 [配置接入](chrome133-integration.md)，其他浏览器策略尚未完成。
ECH/REALITY 组合验证记录位于 `target/browser-advanced-stage`。
ECH 保留 Chrome 外层，内层版本只允许 TLS1.3，避免通过外层扩展压缩带入 TLS1.2/GREASE；
这遵守 [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1) 的版本边界，
尚不宣称内层编码与浏览器逐字节一致。测试包含四种 group、HRR、恢复、分片、认证重试和
不可信公开证书。REALITY 按固定 sing-box 的额外模板修改处理，见
[REALITY 包装差异](android11-chrome133-wire-audit.md#reality-包装后的差异)。
这些验证通过同一构建锁排队。密码实现和产品依赖继续使用 Rust；Go 只作为独立测试对端。

## TLS 1.2 安全重协商

`ClientConfig.enable_tls12_renegotiation` 默认关闭，显式启用后最多允许一次服务器发起的
重协商。先校验前次双方 Finished 的 RFC5746 绑定，再完成完整证书/签名/Finished 认证，
保持相同 leaf 证书和 ALPN，拒绝 EMS 降级和 TLS 版本改变。没有 EMS 的旧恢复会话
按 RFC7627 禁止重协商；没有 EMS 的连接禁止 key exporter。

记录层保留当前密钥和序号直到 CCS，双向新密钥各自从序号 0 开始。旧 epoch 的在途
应用数据可进入有界接收缓冲，新 epoch 在 Finished 之前不能交付应用数据。
Chrome133 缓存首个公开 ClientHello 的布局，重协商更新绑定，不重新随机化 GREASE/
扩展次序/公开 key share；实际 TLS1.2 ECDHE 仍重新生成临时密钥。缓存仅在 opt-in 且
最终协商为 TLS1.2 的连接保留，使用一次即释放；TLS1.3 不长期保存这份缓存。

独立对端的标准 Go / 固定 Chrome133、五套密码和九种模式共 90 组自测通过。
Rust 开发/优化各 75 项通过，新增矩阵覆盖20组正常双向握手和客户端认证，另有错误绑定、
证书变化、ALPN变化、EMS降级、坏Finished、新旧epoch应用数据、分片、会话恢复后
再次完整认证、默认拒绝及第二次拒绝。依据和重现命令见
[TLS1.2 独立对端](../tests/reference/tls12-renegotiation-peer/README.md)。
异步传输适配已合入，生产模块桥接 2 项、14 组组合通过，覆盖短读/短写、Pending、
读写取消、读/写任一方向推进握手和两种 framing。普通 TLS 读操作仍保留原有读写独立性；
只有正在重协商时协同驱动输出。完整内核回归和 Android 更新继续执行，以上计数不代表 APK 已更新。

2026-11-23续验：上述重协商快照的19项异步TLS专项、2,860项完整内核回归和16项独立互通通过。
回归发现的REALITY失败后写入挂起已修复，并覆盖scalar/vectored写入和零输出进度。
四ABI原生构建被主机重启中断，记录位于 `target/android/browser-renegotiation/`。
