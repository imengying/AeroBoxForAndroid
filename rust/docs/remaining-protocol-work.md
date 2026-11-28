# Android 协议兼容的剩余工作

> 2026-11-26 范围收敛：优先完成当前 Android 的设备验收；下文为历史实现台账，不是继续扩大 TLS 兼容工作的授权。新项目不维护旧接口。当前成果与待办见 [设备记录](android-device-smoke.md) 和根 README。

检查日期：2026-11-23。Android 本地基准为 `/home/Code/AeroBoxForAndroid` 的 `7206146effd0ac3602eb5b96ad5986e5af5ced5e`，固定 sing-box `v1.14.4`；该版本绑定 sing-vmess `a0c58542bd9d`。同时核对 sing-box testing `039d829d20c7bfb963dd73113afa9f2d1f080a70`，但兼容目标以原 App 版本为准。[v1.14.4 依赖](https://github.com/SagerNet/sing-box/blob/v1.14.4/go.mod#L58)

这是本轮代码审计时的缺口清单，记录“配置字段、执行路径、线协议、验收”四个层次。协议家族已有实现与通过部分互操作，不代表以下全部选项已经实现。本文所列后续项未计入本轮四 ABI 基线。

平台范围仅为 Android。本文中的 `ios`、`safari`、`firefox` 等是 Android 节点可选择的
`tls.utls.fingerprint` 值，不是对应平台的 App 开发任务。原 Android 的
`viewmodel/nodeeditor/NodeEditFields.kt:259–263` 列出这些选项，
`core/config/OutboundConfigBuilder.kt:434–439` 将值原样写入内核配置。
相关 TLS 密码兼容工作用于这些现有 Android 配置；交付仍为 JNI/Kotlin、Android AAR/APK。

## SS 插件

Android 的 `app/src/main/kotlin/com/aerobox/core/config/OutboundConfigBuilder.kt:37` 对普通 SS 与 SS2022 共用分支，原样输出非空 `plugin`、`plugin_opts`（第 44、45 行），默认 method 为 `aes-128-gcm`。插件选项同时可来自订阅导入和节点编辑；只在第 233 行明确拒绝 `shadow-tls`。Rust 现已通过 `crates/aerobox-config/src/ss_plugin.rs` 转换 SIP003 参数，并接入 `vendor/shoes/src/ss_plugin`。HTTP/TLS obfs 和 WebSocket/TLS/mux 已通过独立对端；QUIC 的复用、重连、证书拒绝与原生 UDP 分流也已通过独立 Go 对端。

| 字段与组合 | 上游行为 | Rust 当前实现与验收 |
| --- | --- | --- |
| `plugin=obfs-local`，未指定模式 | 默认 HTTP；`obfs=http/tls` 选两种封装，`obfs-host` 给伪装 host | 已实现独立 simple-obfs stream 包装和严格参数解析 |
| `obfs=http` | 首个 SS 密文写入 HTTP GET body，带 Upgrade 相关头；后续传原始字节，入站剥首个 HTTP header | 已实现独立 HTTP framing；分片 header、短读、首包合并与半关闭均有回归 |
| `obfs=tls` | 首包放在仿 ClientHello 的 session-ticket extension；后续按仿 TLS application record 发送，单块最多 16 KiB | 已实现仿 TLS 状态机；截断、长度边界、16 KiB 写入及背压有回归，未调用真实 TLS 替代 |
| `plugin=v2ray-plugin`，未给 `mode` | 默认 `websocket`，Host 默认 `cloudfront.com`，path 默认 `/`；`host` 同时覆盖 TLS server name | 已复用 WS/TLS，保留插件默认值；独立对端已通过 |
| WS 模式未给 `mux` | 默认 `mux=1`；正值包一层 VMess/Xray Mux.Cool TCP framing，`mux=0` 才直接传 SS 字节 | 已实现 Xray TCP mux；mux=0/1/8 × plain/TLS × SS/SS2022 已通过独立对端 |
| `mode=quic` | 选择 V2Ray QUIC bidirectional stream；该分支不附 WS 的 mux wrapper | 已接 QUIC carrier、h3 ALPN 与最多16条路由的会话缓存；独立对端、并发和重连测试已通过 |
| 插件 TLS | `tls` 按参数存在性开启；`cert` 为证书文件，`certRaw` 为去头尾的证书内容 | 已接严格 CA 验证和文件 PEM 依赖；WS 错误 SNI 拒绝已通过，QUIC 拒绝用例已通过 |
| 插件 + SS 原生 UDP | 上游插件只介入 TCP；原生 UDP 仍直接走 SS UDP 数据路径 | 原生 UDP 绕过 obfs/WS/QUIC；UoT、multiplex 复用插件流路径；QUIC 原生 UDP 独立对端测试已通过 |

依据：[插件注册和模式](https://github.com/SagerNet/sing-box/blob/v1.14.4/transport/sip003/obfs.go)、[HTTP 编码](https://github.com/SagerNet/sing-box/blob/v1.14.4/transport/simple-obfs/http.go)、[TLS 形状编码](https://github.com/SagerNet/sing-box/blob/v1.14.4/transport/simple-obfs/tls.go)、[v2ray-plugin 默认值与 wrapper](https://github.com/SagerNet/sing-box/blob/v1.14.4/transport/sip003/v2ray.go)、[SS TCP/UDP 分派](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/shadowsocks/outbound.go)。

`plugin_opts` 不能简单按分号再按等号 split：SIP003 允许转义 `;`、`=` 和 `\`，无等号的 flag 表示值 `1`，重复 key 的 Get 取首值，尾部孤立反斜杠与空 key 报错。[上游参数解析](https://github.com/SagerNet/sing-box/blob/v1.14.4/transport/sip003/args.go)

严格纯 Rust 路径是在已有 AsyncStream 外加 Rust framing，不启动外部 `obfs-local` C 可执行文件，也不内嵌 Go v2ray-plugin。参考对端可用于测试，不进入发布 AAR。验收先覆盖 HTTP/TLS obfs 的 SS AEAD 与 SS2022、原生 UDP 绕行；再覆盖 WS plain/TLS × mux 缺省/0/正值、QUIC 与错误证书。

## VMess alter_id、CFB 和 security=zero

Android `OutboundConfigBuilder.kt:53` 总会输出 `alter_id`，默认为 0；`security` 默认 `auto`。`NodeEditFields.kt:81` 直接提供 `zero` 选项，CFB 虽不在编辑列表，订阅导入及数据库字符串仍可能保留。本轮新增 `vmess/legacy.rs` 和统一 `vmess/client.rs`，接入 `alter_id`、CFB 和 zero；独立 Go 服务的 `alter_id={0,1,64}` × `{CFB,AES-GCM,ChaCha20,none,zero}` × TCP/原生 UDP/packetaddr/XUDP 矩阵已通过。

| 输入 | 当前行为 | 所需兼容工作 |
| --- | --- | --- |
| `alter_id=0` + AES-GCM/ChaCha20/none | 已有 AEAD header，相关 TCP/UDP、padding/length/packet encoding 已进入 Go 互通矩阵 | 保留现有回归 |
| `alter_id>0` | 已接 legacy 请求/响应头，独立 Go 矩阵通过 | alter UUID、时间 HMAC-MD5、AES-CFB header；正数与数据 cipher 独立，响应 key/IV 用 MD5；客户端与固定版本一样使用第一个派生 alter UUID |
| `security=aes-128-cfb` | 已接持续 CFB128 状态、加密长度与 FNV-1a checksum，独立 Go 矩阵通过 | 不同认证模式下 response CFB 的起点不同；需分片、损坏校验、TCP/UDP 及参考对端矩阵 |
| `security=zero` | 已作为 none 的别名接入 security 5，独立 Go 矩阵通过 | TCP/Mux 默认不分块，UDP 保留分块；padding/authenticated_length 仅对 AEAD 数据 cipher 启用，匹配原 App 所用版本 |
| `security=auto` | Rust 目前选 ChaCha20 | 上游按体系结构选 AES-GCM/ChaCha20；互通兼容，但自动选择的性能行为尚不一致 |

原 App 版本的 none/zero TCP 默认不设置 chunk stream，UDP 设 chunk；padding 与 authenticated length 仅在 AEAD data cipher 的生成分支启用。本轮已将 Rust 客户端默认字节行为对齐，并保留服务端接收先前 chunked none 的能力。[固定版本 client.go](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d/client.go#L34)

CFB 的 header 与 payload 是两条独立兼容维度。旧 header 使用时间认证、派生 alter key 和 CFB；数据类型 security 1 则使用 CFB、长度分块和 checksum，response 密钥/IV 也须按 header 模式选择。RustCrypto 现有 AES/MD5/HMAC 基元足以作为实现基础；固定向量、错误校验、分片边界、取消恢复和 Go 对端矩阵均已通过；认证或 checksum 错误使读取状态永久失败，后续读取不能泄出先前缓存的明文。[固定版本 protocol.go](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d/protocol.go)、[VMess 协议文档](https://www.v2fly.org/en_US/developer/protocols/vmess.html)

矩阵包含 131071 字节 TCP 载荷、原生 UDP 到 15000 字节、packetaddr 到 14993 字节、XUDP 到 32768 字节；本地 XUDP 分片和短写测试另覆盖 65535 字节上界。参考 Go 服务的数据 writer 会在 15000 字节处分块，因此原生 UDP 和 packetaddr 的回显测试按它的能力上限执行，未把这一服务端行为写成 Rust wire 限制。上游将 legacy authentication 标为 deprecated，这是协议状态说明，不能代替用户要求的兼容实现或静默改写输入。

当前配置 `alter_id` 范围为 0..65535；零保持 AEAD 认证默认，正数选择旧认证，矛盾的显式 `aead=true` 会报错。Android 客户端出站是本轮兼容目标；本地 VMess 入站继续要求 AEAD 认证，但已接 CFB 与未分块 none 数据，以保留本地协议测试。独立 Go 参考服务通过命令参数选择 legacy alter ID 数量，不进入产品依赖。

空 UDP 的能力按实际编码区分：CFB/AEAD 原生 UDP 以 checksum/tag-only 分块表示空包；none/zero 的零长度分块表示 EOF，所以发送空包会返回 `InvalidInput`，可用 packetaddr 的非空地址头承载空 payload。XUDP 的固定参考实现将零长度 DATA 当作控制帧忽略，因此空包也明确拒绝；普通数据包上限为 u16 的 65535 字节，底层 8 KiB 分块不限制单个 XUDP 数据包大小。此前 XUDP 静默丢弃空包和超过 7526 字节数据的行为已修正，独立对端大包与拒绝空包后继续发送的测试已通过。[固定版本 mux.go](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d/mux.go#L179)

## Dial 字段

Android `OutboundConfigBuilder.kt:240` 的 `applyDialFields` 可输出下表所有拨号设置；AnyTLS 唯独不输出 `tcp_fast_open`。第 200 行还为域名入口或 Naive 自动加 `domain_resolver={server:"dns-direct",strategy:"prefer_ipv4"}`，用于代理入口，与应用目标解析分开。

| Android JSON 字段 | 当前转换/执行情况 | 接续工作与验收 |
| --- | --- | --- |
| `bind_interface` | 转换器第 59 行保留；TCP/UDP 在 `socket_util.rs` 调 bind_device | 已有 OS 绑定，Android 与当前 physical Network 的关系要一致；错误接口必须失败，不得退回默认网 |
| `domain_resolver` | 已接 direct TCP/UDP 的目标解析；代理入口仍使用命名 resolver 和循环依赖校验 | 路由按 IP 规则或 resolve action 已固定的地址继续使用；只对尚未解析的目标应用出站 resolver，避免重新解析绕过规则 |
| `connect_timeout` | 已接 Go duration、DNS/候选与代理握手超时；取消释放连接 | 实际 SOCKS 握手超时测试已通过；后续协议自身更短的硬上限仍可能先结束请求 |
| `disable_tcp_keep_alive` | 已按 true 关闭 SO_KEEPALIVE | 真实 socket getsockopt 已验证 |
| `tcp_keep_alive` / `tcp_keep_alive_interval` | 已支持 idle、interval；缺省 300s/75s | 分数秒向上取整，超出平台范围报错；真实 socket 已验证 |
| `udp_fragment` | 已设置 IPv4/IPv6 PMTU、DF；显式 QUIC 覆盖在 Quinn 初始化后设置，能力报告保持一致 | Linux socket 选项测试已通过；Android direct 转换保留上游缺省 true，显式 false 优先；其他协议及原生配置缺省 false |
| `tcp_fast_open` | 已设置内核 TFO 并补延迟 SYN 状态机，五项专项回归已通过 | 字面 IP 代理入口可由首个握手写入携带 SYN；direct、域名入口及地址竞争等待真实连接，不发送重复首包；AnyTLS 仍拒绝 |
| `tcp_multi_path` | 已创建 IPPROTO_MPTCP socket；不会把创建失败改成普通 TCP | 本机协议号测试已通过；Android 内核支持及多路径实际流量需要真机验收 |
| `network_strategy` | default/hybrid/fallback 已接入 | 独立于 A/AAAA 候选交错；正在收尾服务代际、四 ABI 和设备验收 |
| `network_type` / `fallback_network_type` | string/array 均已转换并执行 | 使用 Android 全部非 VPN 候选的 wifi/cellular/ethernet/other 类型及精确 u64 handle |
| `fallback_delay` | 已接 Go duration，缺省 300 ms | 任一优选失败立即启动备选；备选胜出后进入 15 秒快速回退，独立于 IPv4/IPv6 250 ms 间隔 |

源码定位：`crates/aerobox-config/src/outbound.rs:59,255`、`crates/aerobox-config/src/document.rs:47`、`vendor/shoes/src/tcp/socket_connector_impl.rs:34,533`、`vendor/shoes/src/socket_util.rs:193,221`。host `Platform` 已扩展 physical_networks 与 protect_on_network，Kotlin 与 JNI 均接入。普通保护仍按默认网络绑定，显式选择直接保护并绑定目标网络，拒绝失效快照。

上游拨号字段中，`domain_resolver` 对 direct 作用于请求目标，对其他出站作用于代理服务器地址；`network_strategy` 是物理接口选择。文档说明 fallback 会在优选网络不可用时进入短期并行回退状态。这是需要实现的调度行为，不等同于任选可用 IP。[官方 Dial Fields](https://sing-box.sagernet.org/configuration/shared/dial/)、[固定版本 dialer 实现](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/dialer/default.go)

TFO 的 `TCP_FASTOPEN_CONNECT` 成功和 socket 可写不表示 SYN 已发出。`tcp/fast_open.rs` 在 TCP 实际建立前保留原截止时间；首次读或无应用数据的地址竞争在同一 socket 发送零长度请求以触发 SYN，之后等待真实连接状态。只有字面 IP 代理入口可以把首个协议写入用于 TFO；域名入口目前不尝试在多个候选上重放首批数据。内核不支持 TFO、禁用 TFO、MPTCP 不可用、Android protect/bind 拒绝等错误都直接返回，不自动换普通 socket；权限错误不会被当作可忽略的功能缺失。[Linux 延迟连接与 poll 行为](https://github.com/torvalds/linux/blob/v6.17/net/ipv4/tcp.c#L606)、[延迟 SYN 条件](https://github.com/torvalds/linux/blob/v6.17/net/ipv4/tcp_fastopen.c#L416)

## 当前接续顺序

1. Android11、Edge85/QQ11.1主工程验证已完成；继续实现其他TLS浏览器指纹与Naive Chromium行为，保持严格Rust密码边界。Android11的真实TLS1.0/1.1/1.2、73次独立Go连接、密码开发/发布各111项、内核2866项及Android入口22项已通过，见 [Android11接入](android11-integration.md)。Edge85/QQ11.1已合入主源码，后续内核2867项、Android入口29项和四ABI依赖审计通过，见 [Edge/QQ接入](edge-qq-integration.md)。Android的Safari16/iOS14指纹也已于2026-11-25合入；密码开发/发布各176项、内核2874项、Android主机36项、Quinn409项及18项独立互通通过。四ABI优化AAR及八个APK已封存，见 [Android Safari/iOS指纹接入](android-browser-integration.md)。Firefox120已完成主机合并验收并开放Android配置；密码开发/发布各225项、内核2876项及四ABI优化AAR/八个APK通过，见 [Firefox接入](firefox-integration.md)。random已合入主源码，2,881项内核、45项Android主机与18项浏览器生产入口通过，见 [random接入](random-fingerprint.md)；已进入当前封存APK。360与randomized也已完成验收，密码开发/优化各280项、原生专项12项、Quinn409项通过。后续继续Naive剩余行为，真机验收仍待完成。
2. BBRv2、输入兼容、Chrome133、CBC/静态RSA、Naive窗口和TCP Brutal已进入最新四ABI优化AAR与八个APK，138项JVM检查通过。当前封存清单为 `target/android/app-randomized-release/manifest.json`；已包含Android11、Edge/QQ及Safari/iOS指纹。
3. 设备验收，包括 TUN、生命周期、Private DNS、连接 UID、网络切换和实际出口。

其他已知目标继续由总矩阵跟踪：uTLS 浏览器指纹、Naive Chromium 行为等价、kTLS 和真机 VPN。TCP Brutal 已实现带宽协商与 socket 设置，实际加速效果仍需支持该模块的内核验证，详见 [本轮实现与验收](legacy-tls-naive-brutal.md)。严格纯 Rust 约束不因这些选项而放宽；不支持的非默认字段继续显式拒绝。

## P-521 密码支持

`aerobox-crypto` 已补 P-521 SHA-256/384/512 证书签名验证、SHA-512 TLS签名、PKCS#8/SEC1 私钥加载与公私钥匹配、P-521 ECDH；Android `curve_preferences` 可选择 `SecP521r1`。16项密码测试全部通过，其中新增独立 Go 签名/ECDH向量、TLS 1.2/1.3 双向认证、三种证书哈希、两种私钥格式、篡改与无效点检查。密码运算仍由 RustCrypto 完成，Go只用于手动生成测试样本，不参与发布构建。

## TLS ClientHello 分片

Android `OutboundConfigBuilder.kt:420` 到 `422` 输出 `fragment`、`fragment_fallback_delay` 与 `record_fragment`。当前接入 `tls_fragment.rs`，原生字段为 TLS/REALITY 的 `fragmentation`；普通 TLS、Vision、REALITY 和 XHTTP 安全封装都会执行。仅处理首个完整 ClientHello，在 SNI 内部选拆分点；record 模式生成两个合法 TLS record，握手 transcript 字节保持不变。没有 SNI 或首包无法完整解析时原样发送，与上游的最佳努力语义一致。

packet 模式在 Linux/Android 使用 TCP_NODELAY 和 TCP_INFO 的未确认段计数；确认太快（20 ms 内）或载体不提供原始 TCP 时按配置延时，缺省 500 ms。已有 TCP_NODELAY 状态会恢复，计时与未完成字节归 stream 所有，取消一次 flush 后不会重发前缀。QUIC 不接受这些 TCP/TLS record 选项。九项本地专项已通过，包含真实 TCP 的普通 TLS/Vision 和 REALITY/Vision 三种分片组合、认证及双向载荷；独立 Go TLS 1.2/1.3 × 三种分片组合也已通过，载荷 65537 字节。[固定版本分片实现](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/tlsfragment/conn.go)、[Linux ACK 等待](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/tlsfragment/wait_linux.go)

本地两项握手矩阵内部共覆盖 12 组，独立 Go 对端覆盖 6 组；其余状态机测试覆盖首包分段、短写、取消恢复、EOF 与背压。以上验证在 Linux 主机完成，Android TCP_INFO 与实际网络分段效果仍需设备验收。

## ECH 接入与验证范围

`aerobox-crypto::hpke` 已接 12 个纯 Rust HPKE 套件，RFC 9180 九组 Base 向量各含 257 条连续消息，连同 P-521/provider 测试共 18 项通过。Android ECH `config`（字符串/行列表）、`config_path`、`query_server_name` 已映射到 TLS/QUIC 共享策略；文件在配置加载时读取并限制为 128 KiB。只允许一个合法 `ECH CONFIGS` PEM，不支持的版本/套件和损坏配置直接报错。

动态 ECH 通过现有 DNS 路由查询 HTTPS，检查响应 ID、问题、操作码、返回码、截断和完整报文长度；跟随有限 CNAME/HTTPS alias，按最小 TTL 缓存，不保留过期失败结果。同一策略合并并发查询，等待锁与查询共用截止时间，取消释放 DNS 工作。成功认证的配置轮换只更新原 TTL 内的缓存。

普通 TLS、Vision、XHTTP 和原生 QUIC 已接入一次 ECH 拒绝重试。公开名称证书由独立严格 CA/名称校验器认证，即使 inner TLS 设置 insecure 也不放宽；inner pin 不错误应用到公开证书。只有 CertificateVerify、Finished 都通过后才允许读取 retry config，第二次 ECH 成功后才缓存，绝不退回明文 ClientHello。重试保存所有外层传输封装及多路复用层的载体选择。REALITY 的独立认证握手不能与 ECH 合并，显式组合会报错。

独立参考服务 `tests/fixtures/ech-peer` 用标准 Go TLS 和固定 quic-go，实现 TCP/QUIC 的接受、密钥轮换、无 retry 拒绝和不可信公开证书四模式；Go 对端自测八组通过。Rust 到 Go 的 TCP/QUIC × 四模式 × inner verify true/false，共 16 组已通过（`/tmp/aerobox-ech-interop3.log`，1.80 秒）。矩阵验证 65537 字节双向载荷、独立 inner 公钥 pin、公开证书不可信时拒绝重试、动态 HTTPS 查询和命名 domain_resolver；第二次连接使用已经认证的新配置，使 rotate 两次连接共 3 次握手，无重复拒绝。TCP 路径同时启用 packet/record fragment。[固定版本 ECH 选项与 DNS 路径](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/tls/ech.go)

本地 ECH 单元、H2Mux 完整外层重放和 DNS Strategy 三项回归也已通过；真实配置编译的 CA/ECH 文件加载、删文件后仍可构造连接、缺失/损坏文件和 TLS1.2/禁用 SNI 拒绝三项测试已通过。null/IP/缺失 DNS 身份前置拒绝及域名默认身份继承两项也已通过。ECH 快照全库 2811 项通过，另一个旧 XUDP 上限断言已修正并单独通过；11 组独立互通通过。ECH 四 ABI 开发 AAR 已生成，317 项活动依赖无禁用密码后端，64 位 LOAD 对齐 16 KiB。后续多网络改动及设备测试另行验收。

## Android 多物理网络策略的实现与验收

以下实现已接入源码，19 项专项及后续 TUIC 合并快照的 2,837 项全库回归通过，四 ABI 开发 AAR 已重建。原 App 的 `OutboundConfigBuilder.kt:238` 到 `241` 输出 `network_strategy`、`network_type`、`fallback_network_type`、`fallback_delay`；类型列表可以是字符串或数组。`RouteConfigBuilder.kt:31` 固定输出 `auto_detect_interface=true`。本仓库 `dial_fields.rs` 已消费四项并保留强类型值；完整 Android 文档要求 `auto_detect_interface=true` 才可配置显式网络策略，冲突的 bind_interface/TFO 会报错。

兼容基准为 App 固定的 sing-box `v1.14.4`：

- `default` 省略类型时选择默认物理网络；`hybrid` 省略类型时选择全部候选；`fallback` 省略优选类型时选择默认网络，省略备选类型时使用其余网络。显式类型为 `wifi/cellular/ethernet/other`。
- 当前官方文字将 default 的多个接口描述为串行；固定版本 `selectInterfaces` 返回类型集合后，`dialParallelInterface` 实际同时启动所有 primary。以固定源码为兼容目标并用测试明确这一差异，不把两种行为混写成已经验证等价。
- fallback 的正常模式在 300 ms 默认延迟后启动备选，优选连接失败可以立即启动备选；备选胜出后进入 15 秒快速回退窗口，优选恢复时退出。此状态属于出站拨号器，不能做成跨用户/跨配置的全局状态。
- 原生 UDP 的 `ListenPacket` 使用 `serialInterfaceControl`，按优选、备选的顺序选择一个能绑定的接口；不会复制应用数据包来检测哪个网络更快。原生 QUIC 使用这一 UDP 载体，但其握手成功与否仍必须纳入连接结果。
- 固定版本还拒绝显式 `network_strategy` 与 `tcp_fast_open` 的组合，除 `bind_interface`、显式 IPv4/IPv6 绑定冲突外需要一并验证。

依据：[固定接口选择及 TCP 竞争](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/dialer/default_parallel_interface.go)、[UDP 入口与回退状态](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/dialer/default.go)、[地址族和物理接口的组合](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/dialer/default_parallel_network.go)。

当前实现边界：

| 范围 | 具体实现 |
| --- | --- |
| 配置 | `dial_fields.rs` 转换到 `DialOptions` 中的强类型策略、类型列表和 Go duration；区分省略与显式 default；保留 `auto_detect_interface` 的语义并验证冲突，平台无能力时明确报错 |
| 平台快照 | `embedding::Platform`、JNI、Kotlin 增加物理网络快照和按 handle 绑定的方法；快照包含 generation、默认 handle、各网络类型/接口名/DNS。使用 Android `Network.networkHandle` 的 Long 值作为身份，不能只用可能复用的接口名 |
| Android 监控 | 保留默认网络监听，另监听所有 `INTERNET + NOT_VPN` 候选的 available/lost/capabilities/link properties；原 `registerBestMatchingNetworkCallback` 只能发布最优网络，无法构成完整候选清单。快照和 `Network` 对象映射必须一起更新 |
| Socket 绑定 | 新 `protectOnNetwork(fd, generation, handle)` 先执行 `VpnService.protect`，再对借用 FD 的副本执行所选 `Network.bindSocket`；普通 protect 保留默认路径。显式绑定不能先绑定默认网络再尝试改绑；目标网络消失或权限失败不得回落到未保护 socket |
| Rust 调度 | 独立模块持有一轮拨号的快照、优选/备选和快速回退状态；与现有 A/AAAA 候选交错分别计时。所有尝试共用总截止时间与资源预算；胜出、取消、截止或配置关闭后释放其他 socket，后台探测若用于恢复状态也必须受同一生命周期约束 |
| TCP/UDP/QUIC 接线 | `socket_util` 的 TCP、UDP 构造接显式网络绑定；direct、SS/SOCKS 原生 UDP、代理链外层载体共用。显式策略的 QUIC 端点已改为按 host/generation/handle/address family 懒建并隔离缓存，HY2 hopping 继承绑定 |
| 复用与网络切换 | 网络 generation 改变时使旧候选和复用缓存失效；池键或其所有者生命周期包含网络身份。ECH reopen 重建完整外层包装并重新通过同一出站策略选网，仍受总截止时间和取消信号约束 |
| DNS | 明确的 domain_resolver/detour 继续按自身配置执行；默认物理 DNS 快照与默认绑定保持一致。不能为某一连接赢得比赛而修改全局 bootstrap，使其他连接的 DNS 被无意切网 |

验收先使用可控平台回调和真实 localhost socket：验证每种选择、300 ms 与立即回退、15 秒恢复、错误接口、protect 失败、取消/超时、落败 FD 回收；原生 UDP 只发一份，QUIC 不跨网络复用端点；再验证 JNI/Kotlin 和四 ABI。真实 Wi-Fi/蜂窝同时在线、移动网络未激活时的行为、切换中的 DNS/连接恢复和实际出口仍需要 Android 设备验证。

Android Kotlin session 已增加单线程网络刷新队列：默认网络和候选清单变化共用 revision，合并连续通知，启动中只记录变化，停止时注销 callback 和 worker。`scripts/test-kotlin-lifecycle.sh` 使用真实 session 类与模拟 Android/JNI 边界，5 项并发与清理测试通过；这不替代设备上的实际出口验证。Rust 首轮 16 项专项包含调度时序/取消/失败、u64 快照、真实 TCP/UDP 和 QUIC 端点复用/退休。附加的迟到恢复、服务身份防回退和 DNS wrapper 生命周期测试均已通过。Android host 10 项生命周期全部通过，覆盖真实 TCP 多网络恢复、服务重启以及 1 MiB 调用线程栈；启动阶段和运行控制阶段的大型 future 已移到堆上，避免调试构建的栈溢出。

## TUIC 后续确认的线协议差异

固定 sing-box v1.14.4 的 `udp_over_stream=true` 使用 UoT v2，经 TUIC CONNECT 双向流访问 `sp.v2.udp-over-tcp.arpa:0`；`udp_relay_mode=quic` 则使用 TUIC COMMAND_PACKET 单向流，二者不同。转换器与运行时现已修正，显式非空 udp_relay_mode 与 udp_over_stream 的冲突也按上游拒绝。2 项配置回归、原生配置校验和独立 Go UoT 互通通过：IPv4/IPv6/域名 × 空包/3/16,384/65,535 字节、取消读恢复、共享 TCP/UDP 会话、网络退休；对端记录确认没有使用 COMMAND_PACKET。

`zero_rtt_handshake=true` 已接入独立握手完成/拒绝状态、64 KiB 有界早期数据重放、确认后单次 AUTH、共享初始化及网络切换取消。早期 read/flush/FIN 和原生 UDP 等待确认；只有真实早期数据被拒绝或经过认证的 ECH 换腿才重放，普通 I/O 错误、证书失败不能触发重试。初始化和重试使用同一截止时间，配置拒绝不支持的 hybrid-only 组合。

本地真实 TLS resumption 状态机测试通过；固定 sing-quic Go 对端覆盖 accept/reject-after-first/disabled × native/quic/UoT 九种组合，TCP 200,003 字节与 UDP 空包/3/16,384/65,535 字节，确认同一会话且没有重复 CONNECT。ECH Go 对端另外覆盖八种 0-RTT 接受、拒绝、密钥轮换、坏公开证书、取消与截止边界。14 项独立互通全部通过，合并快照全量 2,837 通过、34 个需外部环境测试默认忽略；其中本轮涉及的互通测试已显式运行。

## 原 App 最小替换规模

只读盘点发现 6 个 Kotlin 文件直接 import libbox：`SingBoxNative.kt`、`AeroBoxVpnService.kt`、`DefaultNetworkMonitor.kt`、`PlatformInterfaceWrapper.kt`、`LocalResolverTransport.kt`、`VpnTunController.kt`。`SingBoxNative` 集中 7 个不同 Libbox 调用；服务负责 CommandServer 生命周期、3 个诊断入口、TUN 和平台回调。保留现有 `SingBoxNative` facade 的初始化任务、StateFlow、错误返回和统计数据类，可避免同时修改 Application、Settings、订阅校验、配置检查和数据导出等上层调用。

最小实际迁移还需要调整 `VpnRepository.kt:237` 的测速平台参数与 `AeroBoxVpnService.activePlatformInterface()` 返回类型，替换 `app/build.gradle.kts:150` AAR 依赖及旧 gomobile ProGuard 规则。已准备的 `RustVpnSession`、`RustTunController`、两个平台回调可接管对应功能；具体调用见 `android/APP-INTEGRATION.md`。原 App 工作区当前存在用户对 `README.md` 的修改，本轮未改动原 App 任何文件。

已在 `/home/Code/AeroBoxForAndroid-rust`（`codex/rust-core-migration`）实施八文件迁移，保留服务 operation/revision、启动中停止、前台通知、重连和三并发测速逻辑。最新包含random、360与randomized的浏览器指纹合并快照AAR已完成Debug、未签名Release/R8/资源压缩/lintVital和138项JVM验证，四ABI共八个APK及SHA256记录位于 `target/android/app-randomized-release/`。更早的Chrome133、TUIC/多网络及平台APK已清理，旧清单和哈希保留。

新统计是会话总量，当前 UI 的 proxy+direct 合并查询已适配，任意 outbound tag 查询仍明确拒绝。原始 TUN tuple 的 UID/package 和 Android `DnsResolver.rawQuery` 系统 DNS 已接入 Rust/JNI/Kotlin；平台快照 2,849 项全量内核回归、14 项互通、JNI 生命周期/DNS 全链路和 Kotlin 专项通过。后续 CBC/静态 RSA、Naive 窗口和 TCP Brutal 最终快照 2,860 项内核回归、16 项互通通过，最新 APK 已包含。Private DNS、分应用、后台运行和实际出口需设备验收。

## BBRv2和输入兼容接续

2026-11-23：独立BBRv2算法、Quinn包级ACK/丢包/ECN/丢弃/迁移接线和Naive工厂已合入；93项隔离算法测试通过。包采样只保留实际未决包，32位累计字节计数使用u64。完整Quinn修正0-RTT测试夹具后409项全部通过；生产早期数据校验未改变。最终状态见`target/android/bbr2-input/status.json`。

Android单个`curve_preferences`字符串现在归一为一个元素的原生曲线列表。VMess/VLESS出站用户ID按固定sing-vmess兼容：任意合法UUID直接使用，其他UTF-8字符串按nil namespace生成UUID v5；原生服务端UUID策略不变。15组Go参考向量通过，Android公共入口与15组真实认证/数据回环测试通过。合并内核2,866项、Quinn409项、Go互通18项、Android主机21项、配置40项、浏览器专项6项全部通过，该阶段四ABI优化安装包清单位于 `target/android/app-bbr2-release/manifest.json`，138项JVM检查通过。后续最新包见上文浏览器指纹合并快照。
