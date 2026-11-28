# Android 浏览器 TLS、Naive 与内核性能选项：固定版本实施清单

本文件记录源码审计、原始实施顺序和后续修正；下文的原始步骤不代表仍然全部待做。审计以原 Android 提交 `7206146effd0ac3602eb5b96ad5986e5af5ced5e` 和其 `.github/sing-box-version` 指定的 `v1.14.4` 为准；没有修改原 App 工作区。Naive H2/H3、ECH、REALITY、TLS 分片的协议互通与 Chromium 指纹验收分别记录。

2026-11-23更新：下文保留原始实施顺序和完整缺口。Chrome133所需的密码、ALPS、
独立多share、ClientHello、ECH/REALITY和TLS1.2重协商已经实现，并接入Android配置；
40项配置测试和6项生产模块专项通过。当前验收与打包状态以
[Chrome133接入](chrome133-integration.md) 为准；BBRv2已合入并通过93项独立测试，正在完整集成验收；其他浏览器和Naive Chromium行为仍需继续实现。

2026-11-25更新：BBRv2、Android11、Edge85/QQ11.1、Android 的 Safari16/iOS14 指纹已完成
主机及四 ABI 打包验收。Firefox120 也已合入主源码：密码开发/发布各225项、内核2876项、
Quinn409项、Android主机43项与18项独立协议互通通过，四 ABI 优化 AAR 和八个 APK 已封存；结果为
`target/android/firefox/status.json`。`random` 已合入，2,881项内核、45项Android主机及18项浏览器入口通过；该选择器已进入当前封存APK，见 [random接入](random-fingerprint.md)。
`randomized` 与360已完成合并及四ABI封存，密码开发/优化各280项和原生专项12项通过；见 [randomized](randomized-fingerprint.md) 与 [360](browser360-integration.md)。Naive Chromium行为继续推进。实际 Android VPN/网络切换仍待真机。

同日对剩余指纹复核固定 sing-box 提交 `c005f35300ce76427dc285481ec5695f5b179cd2` 和
uTLS v1.8.7，逐个区分模板广告与实际可协商实现。源码、官方 blob 校验和审计结论保存在
`target/remaining-browser-fingerprint-audit-stage/`。下文360相关内容按这次复核修正。

## 可复现参考版本

| 部分 | 固定来源 | 主要文件 |
| --- | --- | --- |
| Android 字段 | 原 App `7206146` | `app/src/main/kotlin/com/aerobox/core/config/OutboundConfigBuilder.kt`，`viewmodel/nodeeditor/NodeEditFields.kt` |
| sing-box | [v1.14.4](https://github.com/SagerNet/sing-box/tree/v1.14.4) | `common/tls/utls_client.go`、`protocol/naive/outbound.go`、`common/mux/client.go`、`common/ktls/` |
| uTLS | [MetaCubeX/utls v1.8.7](https://github.com/MetaCubeX/utls/tree/v1.8.7) | `u_common.go`、`u_parrots.go`、`u_tls_extensions.go`、`u_handshake_client.go` |
| Naive Go 包装 | [cronet-go 0d28acc44093df24b2526dea3d6ffefd6b0a54f0](https://github.com/SagerNet/cronet-go/tree/0d28acc44093df24b2526dea3d6ffefd6b0a54f0) | `naive_client.go`、`engine_params_experimental_options.go`、`.gitmodules` |
| Naive 源码子模块 | [naiveproxy 72a06c9fca0e2d228588c7f3074bf7efff3ff686](https://github.com/SagerNet/naiveproxy/tree/72a06c9fca0e2d228588c7f3074bf7efff3ff686) | `src/chrome/VERSION` 为 **150.0.7871.63**；`src/net/socket/ssl_client_socket_impl.cc`、`src/net/spdy/spdy_session.cc`、`src/net/quic/quic_context.cc` |
| Naive 原生库 | cronet-go/lib/* `v0.0.0-20260912104006-c10c03c318db` | `sing-box/go.mod:143` 起固定四个 Android ABI；尚未运行该原生库核对 `Engine.Version()` |
| TCP Brutal mux | [sing-mux caf09fe32475](https://github.com/SagerNet/sing-mux/tree/caf09fe32475) | `brutal.go`、`brutal_linux.go`、`client.go`、`server.go` |

`sing-box/go.mod:30,39,40,48,50` 固定以上 Go 依赖；不是以仓库的最新分支推测版本。阅读用副本保存在 `/tmp/aerobox-browser-tls-reference/`。Cronet 包含大型二进制，参考目录只需其文本源码，不需要将其作为产品依赖。

## App 实际发出的配置

- `OutboundConfigBuilder.kt:434` 仅在 `fingerprint` 非空时输出 `tls.utls={enabled:true,fingerprint:...}`。`ProxyNode.kt:98` 默认 `null`，不存在全局默认 Chrome 指纹。
- `NodeEditFields.kt:259` 提供 `chrome/firefox/safari/ios/android/random/randomized` 建议项，字段仍是可编辑文本，导入也保留字符串。固定 sing-box 还接受 `edge/360/qq` 和五个 Chrome 别名；不能把建议列表当输入白名单。
- `OutboundConfigBuilder.kt:404` 同时可输出版本、密码套件、曲线、CA、pin、客户端证书、SNI、ALPN、ECH、分片及 `kernel_tx/kernel_rx`。`buildNaiveTlsObject:303` 也调用它；编辑器对 Naive 隐藏字段并不能阻止导入的配置进入该路径。
- `applyMultiplex:252` 只在 `muxEnabled != null` 时发出 multiplex；SS/SS2022、VMess、VLESS、Trojan 支持该设置。Brutal enabled 为真或任一带宽为正即生成 `brutal`，缺失的带宽各补 **1000 Mbps**，未显式指定 enabled 时补 true。
- Naive 的 `quic/extra_headers/insecure_concurrency/stream_receive_window/quic_session_receive_window/udp_over_tcp` 来自 `OutboundConfigBuilder.kt:133`。这里只讨论 App 能产生的字段，不推断用户是否正在使用某个指纹。

## 指纹对应的真实能力

别名定义在 [u_common.go:605](https://github.com/MetaCubeX/utls/blob/v1.8.7/u_common.go#L605)，具体 wire 模板在 [u_parrots.go](https://github.com/MetaCubeX/utls/blob/v1.8.7/u_parrots.go)。以下仅列当前实现还需检查的差异；现有纯 Rust TLS 1.3、ECDHE AEAD、P-521 签名/交换、X25519+MLKEM768 不是缺口。

| App 名称 | 固定模板及位置 | 必须真实支持的额外行为 |
| --- | --- | --- |
| chrome / Chrome 别名 | Chrome 133，`u_parrots.go:884` | ECDHE-RSA AES-128/256 CBC-SHA；静态 RSA AES-128/256 GCM、CBC-SHA；GREASE；可变扩展顺序；MLKEM768+X25519 两个有效 key share；Brotli 证书压缩；ALPS 新编号 17613；GREASE ECH |
| android | Android 11 OkHttp，`:1742` | 与 Chrome 相同的六个额外 CBC/静态 RSA 套件；RSA-SHA1 签名；该模板无 supported_versions/key_share/ALPN，实际默认范围为 TLS1.0–1.2；独立握手已确认1.0/1.1 CBC可用。不能给它偷偷加 H2 ALPN 或当成 Chrome |
| firefox | Firefox 120，`:1344` | 上述 CBC/静态 RSA，另 ECDSA CBC-SHA；SHA1 签名；X25519/P-256 两个独立 share；FFDHE2048/3072；delegated_credentials、record_size_limit=0x4001；GREASE ECH |
| safari | Safari 16，`:1997` | CBC/静态 RSA/3DES；版本广告含 TLS1.0/1.1；zlib 证书压缩；GREASE 和 padding；没有 Chrome 的 ECH 模板 |
| ios | iOS 14，`:1657` | CBC-SHA1/SHA256/SHA384、静态 RSA、3DES、TLS1.0/1.1；GREASE/padding；部分套件在 uTLS 自身也是 DISABLED |
| edge | Edge 85，`:1788` | Chrome 的 CBC/静态 RSA集合；Brotli；GREASE/padding；无 PQ share，版本广告含 TLS1.0/1.1 |
| qq | QQ 11.1，`:2290` | 类 Edge 85，另旧 ALPS 编号 17513；不能复用 Chrome133的模板 |
| 360 | 360 7.5，`:2109` | 20套件模板；真实密码缺口为ECDHE-ECDSA、ECDHE-RSA、RSA的三种RC4-SHA。四个DHE-RSA、DHE-DSS和RC4-MD5只有FAKE广告，固定uTLS不接受选择；NPN/旧ChannelID也没有后续协商实现 |
| random | `utls_client.go:353` | **进程初始化时**在 Chrome、Firefox、Edge、Safari、iOS 五种模板选一次，非每连接重选 |
| randomized | `utls_client.go:365`、`u_parrots.go:2950` | 进程级 seed；固定强制最大 TLS1.3，其余沿 DefaultWeights；套件裁剪与扩展顺序、版本下限、可选 ALPN/ALPS、多 share 联动。无法用“随机打乱 Chrome”替代 |

需要区分模板字段与参考实现的能力：`u_tls_extensions.go:1708` 起的 FakeRecordSizeLimit、FakeDelegatedCredentials、FakeChannelID 不处理协商结果；`u_common.go:749` 的 EnableWeakCiphers 没有在固定 sing-box 中被调用。Firefox 的记录大小限制与委托凭据现已实现真实协商和验证。360 的六个 FAKE 套件不在固定uTLS的 cipher table，选用会被拒绝；NPN与旧ChannelID也不能仅凭配置字段称为可用功能。后续应分别建模精确广告、可协商集合和明确拒绝路径，不把上游不存在的DHE/DSA/NPN功能当作已支持，也不删广告后仍声称报文等价。若要超过固定上游实现这些能力，应另立实现与验收范围。

## Rust TLS 改造边界与分工

默认 provider 仍提供 3 个 TLS1.3 和 6 个 TLS1.2 ECDHE-AEAD 套件。当前已完成独立 MAC key 的 TLS1.2 CBC key-block/record 路径、四个 ECDHE-CBC-SHA 套件和四个静态 RSA CBC/GCM 客户端套件，显式 cipher_suites 才启用；密码测试及独立 Go 的握手/最大 record/恢复/mTLS/OCSP/错误 keyUsage 已通过，最终快照 2,860 项内核回归及 16 项独立互通已通过。CBC 的 IV 由独立 HMAC-SHA256 派生 AES256 key 与记录序号生成，避免逐record熵源失败引发panic；HMAC内部临时状态未保证清零，不能笼统宣称所有派生状态都清零。这是CBC基础阶段的记录；后续各指纹、TLS1.0/1.1和完整ClientHello的实现状态见本页更新及对应验收文档。精确捕获及覆盖行为见 [Android11/Chrome133 wire 审计](android11-chrome133-wire-audit.md)。

推荐按以下可独立验收的顺序推进，不先开放不完整的 fingerprint 名称：

1. **TLS1.2 CBC/静态 RSA 基础。** 在 rustls fork 增加含 MAC key 长度的记录算法描述和 PRF/key-block 分配，保持已有 AEAD 路径不变。CBC 用 Rust AES/CBC、HMAC-SHA1（后续 SHA256/384）；正确处理显式 IV、序号、MAC、padding、边界、TLS close/alert。解密失败不可暴露 padding/MAC 差别，使用常数时间验证和有上界的内存。静态 RSA 增加可缺省 ServerKeyExchange 的客户端状态、证书 RSA keyUsage/算法验证、48字节 premaster、PKCS#1v1.5 加密、EMS/Finished/恢复；不伪装成 ECDHE。当前目标为客户端，若添加测试服务端的 RSA 解密，也必须独立处理 padding oracle。
2. **受控 ClientHello 构建 API。** 在 rustls 内部、序列化/转录哈希之前应用已验证 profile，包含 cipher/extension 顺序、GREASE 的跨字段一致性、session ID、签名列表、versions、ALPN/SCT/status_request、padding。GREASE 保留码按标准忽略，不属于伪造真实可协商算法。`msgs/handshake.rs:1044` 当前顺序模型会把 ECH/PSK放末尾，需扩展但保留 PSK 必须最后的约束。
3. **多 share 和证书压缩/ALPS。** 当前 `client/hs.rs:301` 只保留一个主交换及其 hybrid component；固定uTLS Chrome133 的 hybrid X25519与独立X25519公钥不同，不能直接复用component；Firefox/randomized另有独立P256 share。都需保存所选share对应的私钥并正确处理HRR。现 rustls 已有 `brotli` / `zlib` feature及解压大小限制，可启用 Rust Brotli、zlib-rs，审计依赖图不引入 C。ALPS 两种编号必须处理服务器设置及客户端 EncryptedExtensions、转录/Finished，不仅放空扩展。
4. **优先完成 Chrome133，再完整 Android11。** 二者共享六个新增套件；Android11虽然报文更小，却实际允许TLS1.0/1.1且缺ALPN，完整支持还需要旧TLS状态机，不能当仅TLS1.2实现。Chrome133只需TLS1.2/1.3，但另需第2/3项，并且hybrid与独立X25519是两个不同公钥。配置检查应拒绝 profile 与 protocol/minmax/ALPN 的真实冲突，不能悄悄改模板。
5. **Firefox，再 Safari/iOS/Edge/QQ，再 360/randomized。** 这是原始顺序；Firefox所需FFDHE、delegated credentials完整认证、记录大小限制，以及Safari/iOS的legacy版本/3DES/SHA256/384 CBC现均已通过主机验证。360按最新审计先补三种真实RC4-SHA、精确模板与EMS策略；其余FAKE广告保持明确拒绝，不以其名称宣称DHE/DSA/NPN已经实现。`random`复用五种完整模板和进程共享选择；`randomized`另行实现生成器与动态握手政策，不能只打乱Chrome。

合适的双路分工是：一人维护 rustls TLS1.2 状态机/记录层和 crypto；另一人维护 profile 参数、配置、捕获对端和独立测试。两人避免同时修改 `client/hs.rs`/`msgs/handshake.rs`，通过已确认的 profile API 汇合。现有代码线数和 fork 范围表明这是 TLS 实现工作，不是单个配置开关。

ECH 必须应用于最终 inner/outer ClientHello，更新其 AAD、压缩扩展和 PSK binder；真实 ECH 取代 profile 的 GREASE ECH，不能产生两个扩展或降低外层证书验证。REALITY session ID 也必须基于最终 ClientHello计算。需保留普通 TLS、Vision、REALITY、ECH、fragment/record_fragment 的现有路径；固定上游明确拒绝 REALITY+ECH，不应新增未验组合。`ClientTransport.reopen` 的一次可信重试与原期限、网络代际、取消约束仍需成立。

## 指纹验收矩阵

- 建立只用于测试的固定 Go/uTLS 客户端，导出 profile JSON和原始 ClientHello；比较完整结构、字段顺序、GREASE对应关系、扩展payload、record拆分。随机数、公钥和真实随机shuffle按规则归一化；JA3/JA4相同不等于验收通过。
- 用独立对端逐个强制选择**每个广告的有效 cipher/group/signature**，完成双向数据、Finished、恢复及关闭；CBC检查不同padding长度、篡改MAC/IV、截断、最大记录、空记录、重复poll后禁止吐出旧数据。
- TLS1.3完整握手/HRR/票据/0RTT拒绝、Brotli/zlib有效和超大解压、ALPS两个编号、随机profile可重现、ALPN覆盖与错误版本均需测试。
- ECH accept/rotate/reject/badpublic × verify true/false，确认outer信任不受inner insecure/pin短路；profile+REALITY、Vision、两种分片复用现有独立Go验收。
- 所有新原语通过向量，四ABI normal/build依赖图和ELF审计保持无 OpenSSL/ring/aws-lc/C密码实现。测试参考对端的Go/Cronet允许独立运行，但不能进入产品链接图。

## Naive：先修语义，再验 Chromium 行为

固定 sing-box [protocol/naive/outbound.go:46](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/naive/outbound.go#L46) 使用 Cronet，而非 uTLS。它拒绝 insecure、disable_sni、定制ALPN/minmax/cipher/group、客户端证书、fragment、kTLS、utls、REALITY；允许CA/SNI/ECH。现 App 导入可能发这些字段；兼容策略应明确，不把接受字段误称为原版支持。

Cronet 源码子模块是 Chrome **150.0.7871.63**，与 uTLS Chrome133不同。`ssl_client_socket_impl.cc:207,762,827,862,879` 启用GREASE、禁3DES/ECDSA-SHA1 CBC、应用ALPS/ECH和扩展乱序。需要按此固定来源进一步提取默认cipher/group、HTTP2 SETTINGS与HPACK、HTTP3/QPACK/QUIC transport parameters；不能拿 Chrome133的 TLS 模板代替。现有纯Rust H2/H3互通只证明代理协议和数据转发。

已确认的窗口语义来自 [cronet-go/naive_client.go:394](https://github.com/SagerNet/cronet-go/blob/0d28acc44093df24b2526dea3d6ffefd6b0a54f0/naive_client.go#L394)：

| 模式 | Android默认 | 显式字段 |
| --- | --- | --- |
| H2 | session=128 MiB，stream=64 MiB | `stream_receive_window=W` 实际设置 session=W、stream=floor(W/2)。**4/2 MiB仅iOS分支**。`quic_session_receive_window`不作用于H2 |
| QUIC/H3 | stream=6 MiB，session=15 MiB | `stream_receive_window`直接设置stream；`quic_session_receive_window`直接设置session |

Android 转换器已按上表修正，零值按 Cronet 当未指定处理；原生 `naiveproxy/options.rs` 两窗口的默认值仍为 256 KiB。H2 实际 SETTINGS/WINDOW_UPDATE 与 H3 独立 Go 对端读取的 transport parameters 均已验证。H2 官方默认达到现有 session128MiB/stream64MiB 上限，无需提高上限。窗口是接收信用而非启动预分配，但在并发/慢消费者下可成为内存压力；保留现有上限，超界显式错误，QUIC 流窗口允许大于连接窗口且不再被静默夹紧。

`naive_client.go:28` 的 BBR=`TBBR`，BBRv2=`B2ON`，Cubic=`CQBC`，Reno=`RENO` 是不同QUICHE算法/选择。BBRv2现已通过独立算法、Quinn包级接线和Naive工厂实现，不映射到旧BBR；93项算法专项、409项Quinn回归和独立Go互通通过。详见 [BBRv2与输入兼容](bbr2-input-compatibility.md)。

Naive 窗口/配置精确转换已完成，后续为：独立 Cronet 客户端握手与 H2/H3 捕获 → Rustls/H2/Quinn 可选 Chrome150 profile → 双向传输及完整指纹验收。原生 Cronet 通过 C/C++ 库实现，`with_purego` 也只是动态加载该库，不满足纯 Rust 产品要求。参考程序可在测试环境独立使用固定原生库，不作为工程依赖。

## TCP Brutal：协议交换与内核能力分别实现

固定 [sing-mux/brutal.go](https://github.com/SagerNet/sing-mux/blob/caf09fe32475/brutal.go) 通过 mux 内第一条TCP流的目标 `_BrutalBwExchange:0` 交换带宽。客户端发送u64大端接收B/s；服务器返回1字节布尔，true后u64大端接收B/s，false后uvarint长度及错误字节。最低65536 B/s；转换应使用checked乘法从Mbps到B/s，不先溢出。

`client.go:195` 在Brutal开启时复用首个session；`:245` 的新session必须交换成功才加入池；`:278` 取min(本端上传,远端接收)设置本地TCP。`brutal_linux.go` 调 TCP_CONGESTION="brutal"，再用 IPPROTO_TCP/23301 设置 repr(C){u64 rate,u32 cwnd_gain=20}；ABI长度必须按目标布局，不能写死64位长度。

已新增 `MultiplexConfig.brutal`、共享 session 建成前的控制交换、原 deadline 和取消处理、失败关闭连接不入池以及网络代际退休。通过受限底层 socket 控制句柄设置 TCP 选项，TLS/SS 包装传递控制能力；QUIC/H2 逻辑流及嵌套 mux 不提供独立 TCP 句柄。控制句柄不提供 I/O，不能绕过加密或计数。当前 HY2 Brutal 是 QUIC 算法，不能替代 TCP 内核拥塞控制。三种 mux × padding 的独立 Go 交换、拒绝、TCP/UDP 与连接复用测试已通过。

参考版行为要精确保留并可观测：**客户端内核模块不存在时只debug并继续**，远端控制交换失败则连接失败；服务端无模块通常返回失败，测试debug模式例外（`server.go:148`）。所以Android没有tcp-brutal模块不必使所有配置失败，但应报告本地加速未启用，不宣称已生效。内核模块本身不由纯Rust用户态库实现。验收覆盖三种mux×padding、交换拒绝/截断/超时、上下行min、32/64位ABI、无模块回退、重连和池隔离；真正拥塞控制效果还需加载模块的独立环境。

## kTLS：原 App 的构建边界

App CI和Release的 `LIBBOX_BUILD_TAGS` 是 `with_gvisor,with_quic,with_utls,with_v2ray_api,with_naive_outbound`，未启用 `badlinkname`。构建脚本虽传 `-checklinkname=0`，仍不满足 [ktls_linux.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/ktls/ktls_linux.go) 的 `linux && go1.25 && badlinkname`；实际进入 [ktls_stub_nolinkname.go](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/ktls/ktls_stub_nolinkname.go) 并返回需重编译错误。因此这是App能发出、默认构建却不能工作的选项，不应当成现有可用功能。

当前 converter 对 kernel_tx/rx=true明确拒绝是可解释边界。若以后实现，应在认证握手完成后安全转移序号/traffic secret，设置TCP_ULP="tls"及SOL_TLS TX/RX，保留KeyUpdate、alert、close_notify、内核能力检测、socket ownership和回退；旧Android内核未必支持TLS1.3 RX或rekey。Rust syscall本身不引入C密码库，但实际record加密由Linux内核完成，不能将该运行模式描述为“所有密码计算均由Rust实现”。它不应挤占当前可用App协议和浏览器TLS的实现顺序。
