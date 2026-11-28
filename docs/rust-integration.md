# Rust + Kotlin 同仓库整合（2026-11-26）

## 来源与范围

Rust 来源为独立 core 的 `4c312077739ec7e2e94ac9cef1e29437f1ce017e`。导入前工作区干净，3,946 个受版本控制文件逐文件复制并校验；源码、锁文件、第三方许可及必要测试均纳入当前仓库 `rust/`。9 个 Kotlin 平台桥接文件从 Rust 工程移至 App 原生接口目录。没有复制原仓库的构建缓存和重复安装包。

已阅读 core 会话（`01a1f50f-ac43-75c2-96eb-6533722bc13f`）的全部用户要求和各轮接续结论。当前约束：只开发 Android，协议与密码实现均使用 Rust，目标是原 sing-box App 实际使用的功能；不新增原 App 没有的协议或服务端功能，不保留旧内核 API 或旧版迁移层。构建串行并限制资源，模拟器与构建错开。

原实现基线是 `main` 中的节点模型、编辑器、配置生成器和裁剪的 libbox 注册表。包括 SS/SS2022、VMess、VLESS/Vision/REALITY、Trojan、AnyTLS、Hysteria2、TUIC、Naive、SOCKS、HTTP，及其原有传输、TLS、DNS、分流、测速和平台能力。历史文档中的“后续研究”不自动成为新的功能需求。

## 当前整合

- Kotlin 桥接直接随 App 编译和压缩；JNI 与回调保留规则进入 App。
- Gradle 自动从 `rust/` 编译所选 ABI 的 `libaerobox.so`；Cargo 锁文件和纯 Rust 检查保留。
- 本地和 CI 使用相同源码与任务，不依赖外部 AAR、相邻 core 目录或另一个仓库的访问 token。
- 只修改 Kotlin 时复用已有 Rust 库；原生修改触发 Cargo 增量检查。默认仍构建原 App 的四个 ABI，本地可选择一个。
- BBRv2 许可继续随 APK 发布；其他依赖许可保留在源码目录。

按全新项目继续精简：只接受当前 Android 配置，删除原型 schema 标记、混合 native 文档、旧 DNS 结构和无作用的 V2Ray 统计配置；Kotlin 删除旧 DNS/服务器占位符与备份主题别名转换。当前订阅格式与备份恢复功能保留，不增加版本迁移，不升级依赖。

JNI 删除未使用的 reload 和按已有标签测速入口。切换节点使用会话重启，测速使用带完整配置的入口。Rust 启动、检查、测速直接将解析后的 JSON 值转换为运行时结构，去掉中间的 JSON 序列化和再次解析；TUN 借用、复制与停止语义保持一致。

## 原 App 功能差异修复

HTTP/gRPC 传输现在接收并执行原有 `idle_timeout` / `ping_timeout`，按入站活动判断空闲，PING 超时关闭失效载体；零空闲超时禁用探活，默认 PING 超时与原实现一致。普通代理会话保留原来的生命周期。HTTP 多 Host 在每次建立载体时择一，HTTP/H2/HTTPUpgrade/WebSocket 的多值请求头保留为重复头；WebSocket Host 仍要求单值，并继续拒绝覆盖协议握手关键头。

原 libbox 构建未启用 `with_grpc`，实际使用 grpc-lite，其 `permit_without_stream` 只需保留输入兼容。HY2 `brutal_debug` 仅开启 debug 诊断，原 App 生成的日志级别固定为 error，因此接收此布尔字段，不额外改变带宽或拥塞行为。原构建未启用 kTLS 所需的 `badlinkname`，旧 ECH 两个开关也不由 Kotlin 输出，这些不扩展实现。

## 首轮验证与接续

本轮从仓库内新源码构建 x86_64、arm64 的 Debug 和经 R8/资源压缩的 unsigned Release APK，全部成功。原生库使用 `dev` profile，不能标作优化 release 内核；CI 默认仍使用 Rust release 并支持四 ABI。活动依赖和 ELF 检查通过，未发现 Go/libbox、Cronet 或 C/C++ 密码后端；R8 后 14 个 JNI 入口及 8 个平台回调均保留。

现有 131 项 Kotlin 单元测试、52 项 Rust 配置回归、6 项新增传输配置检查、4 项独立 HTTP/2 保活和 3 项请求头检查通过；迁入 App 的 Kotlin 生命周期/网络 10 项、DNS 7 组及连接归属 6 组也通过。完整 lintRelease 无错误，有两条警告：动态 ABI 列表未被 ChromeOS ABI 检查识别、进程级测速回调的 Context 静态引用提示。

在 Android 35 x86_64 模拟器，直接运行新 APK 的 ConfigGenerator 和匹配 JNI，41 项检查覆盖全部 11 类节点的 VPN/测速配置、随包 SRS、路由、DNS、IPv6、FakeIP、远程规则以及本轮选项。实际 App 建立 TUN，SOCKS TCP/UDP、域名解析/FakeIP、带认证 HTTP CONNECT 和两类代理访问公网 `example.com:80` 均通过；流量界面显示 112B 上传及 1.02KB 下载，从 UI 停止后 TUN 消失。

模拟器首次启动出现 System UI ANR 和 Wi-Fi 未连接；关闭系统弹窗并重新连接 AndroidWifi 后完成验证。公网参考服务曾遇到上游连接超时，修复参考服务的 IPv4 拨号并重新验证成功。失败尝试没有算作成功。原 App 设置和数据库已恢复，私有备份已删除，模拟器及临时节点已关闭。

本轮限制：arm64 安装包尚未真机运行；其他协议、完整 TLS/QUIC 出口、Private DNS 和长期切网未在本轮重新逐项验收。Naive 完整 Chromium 行为仍不等价，不能宣称已与原 sing-box 版本全部等价。后续继续按原 App 使用场景补真实缺口，不扩展历史研究清单。

构建峰值约 4.50 GiB，无 OOM。验证清单及安装包哈希在 `build/integration/validation.json`；设备记录、截图在 `build/integration/device/`。旧 core 已有的 VPN、DNS、FakeIP、分应用和切网结果保留在 `rust/docs/`，其旧目录和产物链接为历史路径。

新整合保留完整源码，但不把旧的封存 AAR 验证算作新源码验收，也不把配置检查算作所有协议已在设备互通。

本地溯源文件：`build/integration/import.json` 记录导入清单；`build/integration/core-history.bundle` 保留独立仓库的三个提交；`build/integration/previous-device-evidence/` 保留上一轮小型设备记录；`build/integration/core-unmerged-sources.tar.xz` 压缩保留旧 target 中尚未合入的实验源码，仅供溯源，不参与产品构建。它们都是本地交接材料，不参与构建。

## 简化后的验证

按全新项目精简后的代码通过 131 项 Kotlin 测试、55 项 Rust 配置测试和 41 项 APK 内配置检查。重新构建 arm64、x86_64 的 Debug 与 unsigned Release APK，原生库仍用 `dev` profile；R8 后确认保留当前 12 个 JNI 入口和 8 个平台回调，两个废弃入口已消失。构建峰值 4.50 GiB，无 OOM。

Android 35 x86_64 模拟器验证了 SOCKS 域名访问、UDP 回显、FakeIP、带认证的 HTTP CONNECT、界面流量统计，以及两种节点从界面停止后移除 TUN。首次连接操作被系统 UI 的 ANR 弹窗挡住；关闭弹窗后完成验证，不能把启动期间的失败尝试算作成功。

本轮公网 `example.com:80` 请求未通过：参考服务的上游连接超时，宿主机绕过代理直接访问也在 12 秒后超时。这不计入本轮通过项；首轮的公网成功记录只对应当时的验证。当时恢复脚本返回成功并删除临时备份，随后关闭模拟器及参考服务；后续复查发现数据库为空，因此撤回这一轮“数据库已恢复”的结论。详细清单、当时源码和 APK 哈希见 `build/integration/simplification-validation.json`，设备证据为 `build/integration/device/simple-*`。

## 复查发现与修复

复查按原 App 编辑器和原 sing-box 的实际执行条件核对，补齐以下遗漏：

- 关闭 ECH、mux、UoT 后，生成器不再把保留的子参数传给运行时；模型仍保留这些值，重新开启时可恢复。
- Naive 切回 HTTPS、HY2 取消端口跳跃后，不再输出对应的 QUIC 窗口或跳跃间隔。QUIC 节点省略只作用于 TCP 的拨号参数；证书文本与文件路径同时保留时按原逻辑优先文本。
- `network=tcp/udp` 按选中出口的路由条件限制用户流量，覆盖显式规则和最终出口，保留原路由顺序与直连例外。DNS detour 和测速继续使用协议自身能力。
- 证书公钥 SHA256 pin 使用原 App 的独立信任方式，允许正确 pin 的自签证书，仍校验公钥指纹与 TLS 握手签名；pin 与自定义根证书仍冲突。
- CI 补上已有 Rust 配置、HTTP/2 回归和 R8 后 JNI 完整签名检查；清除构建入口遗留的 Go 环境变量。

该次复查时尚有明确能力差异：普通 TLS 1.0/1.1 仍依赖特定浏览器指纹配置，Naive 的完整 Chromium 行为也未完全等价。后续源码修复见下文“普通 TLS 与 Naive 的接续修复”；这里的设备验证只对应当时的构建。Naive 的 uTLS 等原内核本就拒绝的组合不增加实现。原生数组中的内部客户端组仍服务于运行时开发检查，Android 配置层只接收 App 实际生成的节点类型。

复查后的代码通过 131 项 Kotlin、58 项 Rust 配置及 7 项 HTTP/2 测试；新的 CI 回归入口也在本地完整运行通过。重新构建 arm64、x86_64 的 Debug 与 unsigned Release APK，原生库使用 `dev` profile，R8 后 12 个 JNI 入口和 8 个回调的完整签名检查通过。Rust 文件在构建后仅做格式整理，证据同时保留构建时与整理后的哈希。

Android 35 x86_64 模拟器通过 53 项 APK 内配置检查。实际 VPN 验证了 TCP-only 节点阻止用户 UDP、UDP-only 节点阻止用户 TCP，两者的 DNS detour 均能使用节点限制以外的传输。自签名且名称不匹配的 TLS HTTP 代理在正确 pin 下可完成认证 CONNECT；错误 pin、未配置 pin 都拒绝连接，每轮从界面停止均移除 TUN。本轮使用本地参考节点，不计公网或其他协议互通结果。证据和 APK 哈希见 `build/integration/review-validation.json`。

测试环境复查还发现数据库恢复脚本直接覆盖主文件、没有读回或落盘确认便删除备份；缺失的 WAL/SHM 也可能被 `adb exec-out` 的返回码误判为读取成功。本次保留空数据库与原偏好设置现场，从 11 月 9 日经过完整性检查的当前结构快照恢复 7 个原节点和 1 个订阅，保留现有偏好设置并把选择项恢复为原节点。该快照不能证明精确恢复上轮测试前的全部数据，空文件的具体成因尚未确定。测试脚本改为校验备份、写临时文件、读回验证、原子替换、`sync` 和再次读回，保留私有备份并核验系统重启后的内容；这只修改测试辅助流程，不增加 App 的旧版兼容或迁移逻辑。

恢复后经过系统重启、完整退出模拟器再无快照启动，两次均确认数据库和偏好文件与恢复备份逐字节一致，SQLite 完整性检查通过且无临时测试节点。模拟器和本轮参考服务均已关闭，生成的临时 TLS 私钥已移除，恢复用私有备份保留。

## 普通 TLS 与 Naive 的接续修复

普通 TLS 现在可以在未指定浏览器指纹时显式启用 TLS 1.0/1.1，使用已有真实 TLS 状态机和密码实现，不再借用浏览器配置。未指定版本时仍使用 TLS 1.2/1.3；QUIC、ECH 等要求 TLS 1.3 的路径保留其版本约束。普通 `cipher_suites` 按原 Go TLS 语义只限制 TLS 1.2 及更早版本，不会误删 TLS 1.3 套件。显式启用早期版本时才补入所需 CBC 套件，默认配置不因此降级。专项配置、握手和独立 Go 对端用例位于 `rust/tests/tls-options/`。

Naive 使用独立的固定 TLS 策略，对应原 App 锁定的 Cronet/Chromium 150，不通过用户可选的 uTLS 指纹入口实现。TCP 路径配置相应的套件、组、签名算法、Brotli 证书解压、ALPS 与 ClientHello 布局；H2 和 H3 均使用生产 Naive TLS 配置并校验证书链、主机名和自定义根证书。TLS 会话恢复时重新验证缓存证书的当前有效期与信任条件，恢复不能绕过证书校验。原 Naive 已拒绝的 insecure、手动版本/套件、uTLS、REALITY 等组合继续拒绝。

Naive H2 载体接入专用的请求头顺序、空 `user-agent`、padding 形式、CONNECT 的 HPACK 编码、动态表复用、SETTINGS 和流优先级字段，并确保关闭隧道时排出待发送数据和 END_STREAM。使用的是锁文件原有的 h2 0.4.20，同版本源码纳入仓库；这些行为由 Naive 专用开关启用，默认 HTTP/gRPC 路径保持原行为。修改边界与上游来源见 [h2 同版本源码说明](../rust/vendor/h2/AEROBOX.md)。

Naive 窗口使用专用的 checked 整数解析，`KB/MB/GB` 按原 `MemoryBytes` 的 1024 进制计算。H2 默认连接窗口 128 MiB、流窗口 64 MiB；指定 `stream_receive_window=W` 时仍为连接 W、流 floor(W/2)。H3 默认流窗口 6 MiB、连接窗口 15 MiB，两者独立，非零且小于 16 KiB 的值按固定 QUICHE 行为提升到 16 KiB；零输入采用对应默认值。取消内部 64/128 MiB 上限，允许到固定 Cronet C++ 入口实际可生效的 `2147483647` 字节；更大值明确报错。QUIC 协议的 62 位容量不意味着原 App 的 31 位配置入口能设置这些值。H2 显式 W=1 会派生零流窗口，与原实现一致，但不能作为正常传输配置；其线上初始连接信用仍受协议的 65535 字节规则约束。

取消 Naive 并发最多 16 路的内部限制。H2/H3 缓存容量为 `max(16, insecure_concurrency)`，会话随实际请求逐步创建，不按配置值预分配数组或连接；淘汰缓存继续由活动隧道持有会话，保持已有流存活。Kotlin 仅输出正并发值，省略时采用默认 1。回归用例覆盖超过 16 路的循环复用、极大配置只建立实际请求的会话、窗口边界与真实 H2 报文。

独立参考工具锁定原 Cronet 包与源码版本，可分别抓取原客户端和生产 Rust 的 TLS/H2 报文，并检查两个复用隧道的数据与关闭行为，使用方式见 [Naive 参考对端](../rust/tests/reference/naive-profile-peer/README.md)。这些 Go/Cronet 组件只用于测试，不进入 Android 产物。已有 H2/H3 独立对端用例也改为调用生产 Naive TLS 配置，保留双向大块数据、padding、FIN 和 QUIC 窗口检查。

本轮完整内核测试通过 2,898 项，56 项外部环境用例默认忽略；其中 4 项 Naive 独立对端用例另行通过，包含生产 TLS 下的 H2/H3 数据与 FIN、BBR2、QUIC 实际窗口，以及 TLS/H2 报文观察。固定 Cronet 与 Rust 各完成两个 65,537 字节隧道；去除随机字段取值、允许的扩展排列和 padding 差异后，TLS 首包结构、H2 SETTINGS/窗口、CONNECT 编码、优先级及动态表复用对比通过。

CI 回归入口完整通过：61 项配置检查、461 项 h2 库测试（另 1 项原有测试默认忽略）、9 项传输和 6 项生产 TLS 检查；131 项 Kotlin 测试继续使用输入未变的有效 Gradle 缓存。普通 TLS 的 2 项独立 Go 测试另行通过，覆盖 6 个成功与 4 个拒绝场景；3 项恢复策略测试确认旧会话不能绕过当前证书策略、过期检查或提前发送业务数据。

重新构建 arm64、x86_64 的 Debug 与 unsigned Release APK。原生库仍为 `dev` profile；Release 使用 R8/资源压缩。两 ABI 的活动依赖与 ELF 检查通过，四个 APK 的 12 个 JNI 入口和 8 个回调签名通过，随包内核与本轮生成库经相同 NDK strip 后逐字节一致。完整 lintRelease 无错误，保留已有的 ChromeOS 动态 ABI 识别与 Context 静态引用两条警告。构建与测试受 5 GiB RAM/1 GiB swap 限制，无 OOM；完整宿主内核测试编译采样峰值约 4.67 GiB，Android 构建约 4.51 GiB。

Android 35 x86_64 模拟器通过新 APK 的 71 项配置检查。普通 TLS 1.0/1.1 在未配置浏览器指纹时均通过证书校验、认证 HTTP CONNECT 和实际 HTTP 数据访问。Naive HTTPS 与 QUIC 各通过两个 65,537 字节 VPN 回显隧道，使用自定义 CA、`stream_receive_window=96MB` 及 QUIC 192 MB 连接窗口；每轮 UI 停止均移除 TUN。本轮只使用本地独立参考服务，不据此宣称公网或其他协议已重新互通。

早期失败尝试没有计入通过：两项历史路由测试曾依赖跳过证书校验，已改为信任各自真实测试证书；三项配置断言更新为当前 Naive 拒绝信息；独立观察程序修正 FIN/RST 重复计数和误用 CA 作服务端证书的问题，生产证书策略未放宽。源码、日志、APK 哈希和对比结果见 `build/integration/naive-validation.json` 及 `build/integration/naive-review/`；构建开始后只有测试参考服务调整，产品源码未变。

测试前对本轮开始时的数据库和偏好文件另存私有备份。完成后原子恢复、落盘和读回校验；完整退出模拟器再无快照启动后再次确认逐字节一致、SQLite 完整且无临时节点。私有备份保留，模拟器与参考服务已关闭，临时 TLS 私钥已移除。

QUIC/H3 的 ClientHello 布局、传输参数及 QPACK 等报文特征仍未与固定 Cronet 达到指纹等价；H2 的报文对比也不证明包时序、随机分布或全部 Chromium 行为相同。arm64 尚未真机运行，Private DNS、长期切网及其他协议的设备互通没有在本轮重新验收。

## QUIC/H3 接续修复

固定 Cronet 的 QUIC 抓包确认其 TLS 配置与 TCP 不同。Naive QUIC 改为专用 TLS 1.3 布局：3 个套件、9 个签名算法、4 个真实组、独立的混合/X25519 两个 key share、Brotli 与 h3 ALPS；省略 TCP 的 TLS GREASE 槽、OCSP、SCT 和旧版本扩展。保留 ECH 的既有认证路径，握手签名映射中的 SHA1 不会启用 SHA1 证书链或早期 TLS 版本。QUIC 传输参数仍由实际载体生成。

Naive H3 会话缓存现在识别 GOAWAY 与已失败的 H3 状态。GOAWAY 会唤醒全部等待 QUIC 流信用的请求，不要求服务端继续释放信用；仅对尚未发送 HEADERS 的 `RemoteClosing` 重拨一次。已有隧道继续持有旧会话，新请求可以复用替代连接。QPACK 关键接收流持续轮询，FIN、reset 和非法指令及时关闭连接；零动态表容量下仅接收相应合法指令，取消指令解析使用固定大小缓存。

握手完成后的已认证 ALPS 设置通过 Quinn 传至 H3，首个请求即遵守服务端限制。解析限制在 TLS 扩展的 65535 字节以内，拒绝重复/非法设置、不完整帧和禁止帧，校验 ACCEPT_CH/ORIGIN 结构；后续控制流仍须单独发送 SETTINGS，并更新明确提供的设置。ALPS 初值与控制流设置都只初始化一次，请求读取无需新增互斥锁。

独立 QUIC 观察工具与比较入口见 [Naive 参考对端](../rust/tests/reference/naive-profile-peer/README.md#quic-capture)。它分别保留 TLS 字段、传输参数、H3 SETTINGS、QPACK 原始编码以及 FIN/reset 证据；静态 QPACK 对端的成功不等于动态 QPACK 或完整 Chromium 指纹等价。新增 H3 自测入口 `rust/scripts/test-h3.sh` 已纳入 CI，沿用现有产品依赖版本，测试也使用同仓 Rust 密码实现。

本轮通过 259 项 H3、80 项 Naive、175 项 XHTTP、7 项生产 TLS 及 1 项 H3 DNS 测试。另行执行的 6 项 Naive 独立对端检查通过，覆盖真实数据与 FIN、窗口、BBR2、QUIC 抓包，以及错误 CA/主机名拒绝。QUIC TLS 用例同时覆盖两种套件优先级、HRR、会话恢复和过期证书拒绝；GOAWAY 用例覆盖流信用耗尽时唤醒等待者、旧隧道继续收发和新载体复用。

固定 Cronet 与生产 Rust 各完成两个 65,537 字节 QUIC 隧道。去除随机字段取值、允许的扩展顺序并单独列出传输参数后，TLS ClientHello 结构及 CONNECT 语义对比通过；TCP TLS/H2 对比继续通过。QUIC 传输参数、H3 SETTINGS、请求头编码与顺序、QPACK 动态表及关闭报文仍有差异，因此不能宣称完整 Chromium/QUIC 指纹等价。独立观察程序已补上截断帧检查，只有完整帧边界的 EOF 计为正常 FIN。

## 恢复与最终验收（2026-11-27 至 28）

开发继续使用 `/home/Code/AeroBoxForAndroid` 的 `rust` 分支，基于原提交 `19992ceffcde152ee27d3df10b4af1cff8ed40fc`，不引入另一任务在 `main` 上的依赖升级。恢复的 4,489 个文件和 1 个删除项均与交接清单一致；4,061 个构建/测试源文件与上述 QUIC 验证时逐字节一致。源码、构建缓存和产物均已收回原目录，临时 worktree 已移除。暂存备份 `9ee2cbaed1030b041a3d6e741613c27344435667` 保留。

上述宿主测试原始日志保留在 `build/integration/quic-review/`；本轮打包与设备记录位于 `build/integration/quic-review-final/`，其中 `previous-tests.json` 记录原始日志路径、哈希与结果。重新构建 arm64、x86_64 的 Debug 与 unsigned Release APK，131 项 Kotlin 测试全部重新执行通过；四个 APK 的 12 个 JNI 入口、8 个回调签名和随包原生库一致性检查通过。原生库仍使用 `dev` profile，Release 完成 R8/资源压缩，构建采样峰值 4.50 GiB、无 OOM。设备验收使用全新 `AeroBox_RustValidation35` 数据目录。

Android 35 x86_64 模拟器通过新 APK 的 71 项配置检查。Naive HTTPS、QUIC 各完成两个 65,537 字节 VPN 回显隧道，客户端正常退出、内容逐字节一致；使用自定义 CA、96 MB 流窗口与 QUIC 192 MB 连接窗口，每轮 UI 停止均移除 TUN。首次点击被模拟器 System UI 的 ANR 弹窗阻挡，该失败保留在记录中，关闭弹窗后的重试通过。

测试后恢复独立模拟器的空数据库和偏好设置，完整退出再无快照启动，确认两份文件与备份逐字节一致、SQLite 完整且无测试节点。原有模拟器数据未改动；本轮模拟器及参考服务均已关闭，私有基线备份保留。完整清单、APK 哈希及资源数据见 `build/integration/quic-validation.json`。本轮使用本地参考服务，未重新验收公网、其他协议、arm64 真机或长期切网；前述 QUIC/QPACK 报文差异仍存在。

## 动态 QPACK 与 QUIC 连接隔离（2026-11-28）

Naive H3 接入动态响应头解码，实际声明并执行 64 KiB 表容量、100 个阻塞流上限。复用已有 QPACK 编解码基础，增加完整指令分片缓冲、基于最大容量的引用计数环绕校验、动态索引检查，以及响应头/尾部大小限制。解码完成发送 Section Acknowledgement，接收表项发送 Insert Count Increment；取消或丢弃接收流发送 Stream Cancellation。发送方向仍使用静态/字面编码，不宣称双向动态 QPACK 或完整 Chromium 等价。

等待表项期间保留响应头和尾部，取消读取 future 后可继续读取同一响应；QUIC RESET 可在不消耗后续 DATA 的情况下被观察。连接终止与等待者登记共用状态锁，避免漏唤醒。反馈队列有 64 KiB 上限，即使对端不再读取 decoder stream 也能关闭积压连接。仅 Naive 启用动态响应解码，其他 H3 使用路径维持原配置。

Naive QUIC 使用零长度连接 ID，并为每条新连接创建独立 UDP endpoint，实际连接仍由 Naive 会话缓存复用。并发连接、GOAWAY 替换和认证 ECH 重试不复用正在关闭的四元组，原隧道可继续持有旧端点。端点按物理网络保护/绑定，网络代次更新关闭旧端点，登记只保留弱引用。入站流额度调整为原客户端的双向 100、单向 103，并移除未使用的 DATAGRAM 内存预算；不虚报 DATAGRAM 或 QUICHE 私有扩展。

本轮通过 264 项 H3、80 项 Naive、22 项传输、175 项 XHTTP 和 1 项 H3 DNS 测试，另行通过 7 项 Naive 独立对端检查。动态 QPACK 网络用例覆盖分片插入、阻塞取消、远端 RESET、关键流关闭、取消读取后恢复，以及响应与尾部确认；反馈背压和连接错误的唤醒分别有回归检查。独立 Go 服务向固定 Cronet 和生产 Rust 发送同样的动态响应头，两者各完成两条 65,537 字节隧道并返回对应确认。原 TCP TLS/H2 与 QUIC TLS/CONNECT 对比继续通过，其他 QUIC 报文差异仍单独保留。

重新构建 arm64、x86_64 的 Debug 与 unsigned Release APK，131 项 Kotlin 测试全部重新执行通过。四个 APK 的 12 个 JNI 入口和 8 个平台回调签名通过检查，随包内核与本轮生成库经相同 NDK strip 后逐字节一致；Release 完成 R8/资源压缩及必要 lint 检查，原生库仍为 `dev` profile。71 份依赖锁文件保持不变。宿主内核测试编译峰值 5.00 GiB，Android 构建峰值 4.52 GiB，均无 OOM；宿主编译期间仅将软内存阈值临时调到 5 GiB，硬限制仍为 5 GiB RAM / 1 GiB swap。

Android 35 x86_64 上通过新 APK 的 71 项配置检查。Naive HTTPS 和动态 QPACK QUIC 各完成两条 65,537 字节 VPN 回显隧道，内容逐字节一致、客户端正常退出，每轮 UI 停止移除 TUN。动态对端实际收到表项增量和流 0、4 的 Section Acknowledgement。测试仍使用自定义 CA、96 MB 流窗口和 QUIC 192 MB 连接窗口。

早期三次设备尝试未计入通过：一次冷启动后 Wi-Fi 未连接，另外两次暴露观察程序的 Initial 重组问题。夹具改为隔离不同连接、以原始 DCID 派生密钥并认证后续更换 DCID 的包，按测试 CONNECT 目标选取验收连接，避免系统 DNS 流抢占。5 项 Go 回归测试通过；修正后的对端重新通过 Rust 和固定 Cronet 的静态、动态 QPACK 互通及 QUIC TLS/CONNECT 比较。这些修改仅涉及测试对端三个 Go 文件，构建后的产品源码未变，不放宽产品证书校验。

专用模拟器基线已原子恢复，完整退出后无快照冷启动再次确认数据库和偏好文件逐字节一致、SQLite 完整且无测试节点。源码清单、构建资源、APK 哈希与完整证据见 `build/integration/quic-dynamic-validation.json`，详细日志位于 `build/integration/quic-dynamic/`。本轮继续在原仓库的 `rust` 分支完成，不增加仓库或 worktree；arm64 真机、公网、Private DNS 和长期切网未在本轮重新验收，发送方向动态 QPACK 及剩余 Chromium 报文差异仍按前述边界记录。

## HTTP/3 临时响应与 VPN 停止竞态（2026-11-28）

独立对端先发送 `100 Continue`、`103 Early Hints` 再发送成功响应时，旧 Naive QUIC 会错误返回 `Naive CONNECT failed: 100 Continue`。HTTP/3 接收层现在逐节解码并确认临时响应，只把最终响应交给 Naive、HY2、XHTTP 和 HTTP/3 DNS 调用方；取消读取后可以继续等待最终响应。按 [RFC 9114 第 4.1、4.5 节](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1) 拒绝最终响应前的 DATA/EOF 和不允许的 101，101 保持为单流错误。持续临时响应期间主动让出执行时间，不累计保留响应头。

对照固定 Cronet 后确认：其 Naive 封装跳过 100，但把 103 当作错误状态暴露。对等互通验收因此使用 `100 → 200`，Rust 与原客户端均完成两条隧道；103 仍由通用 HTTP/3 状态机用例覆盖，不能宣称这是原 Naive 已支持的能力。原客户端拒绝 103 的日志独立保留，不计入通过。

QPACK 字符串编码先计算 Huffman 长度，只有结果更短才压缩。Naive padding 等会膨胀的字符串直接写入字面值，省去这类字段的临时编码缓冲；压缩路径也不再复制输入字符串。接收端仍能读取两种标准编码。该优化不启用发送方向动态表，也不宣称完整 Chromium 指纹等价。

`RustVpnSession.closeService()` 原先可能在第一次原生停止完成、获取生命周期锁之前，与一次完整的新启动交错，最终仅关闭 Kotlin 侧资源。现在获取锁后再次执行原生停止，再关闭 TUN 描述符与网络监听。新增可控调度用例在修复前直接观察到原生内核仍运行，修复后通过；避免仅通过 Kotlin 的 `active` 状态误判成功。11 项生命周期/网络测试已接入 `:app:testRustVpnLifecycle`，由统一 CI 回归入口执行，沿用 Gradle 自带 Kotlin 编译器。

本轮通过 267 项 H3、80 项 Naive、175 项 XHTTP、8 项 HY2 和 1 项 H3 DNS 回归；独立 Naive 对端的原有检查及新增临时响应场景均通过。真实网络用例覆盖动态临时头的确认、取消读取后恢复、最终响应前 DATA/EOF、101 的错误作用域。抓包确认六个 Rust CONNECT 的 padding 值共减少 159 字节，这是该批具体样本的结果。71 份依赖锁文件保持不变。

arm64、x86_64 的 Debug 和 unsigned Release APK 已重新构建，131 项 Kotlin 单元测试及 Gradle 新入口的 11 项生命周期/网络测试通过。四个 APK 的 JNI 完整签名、平台回调和随包原生库一致性检查通过；原生库使用 `dev` profile，Release 完成 R8/资源压缩与必要 lint。宿主测试编译峰值 5.00 GiB，Android 构建峰值 4.50 GiB，均无 OOM。

Android 35 x86_64 通过新 APK 的 71 项配置检查。HTTPS 与先返回 100、再返回动态 QPACK 成功头的 QUIC 各完成两条 65,537 字节 VPN 回显隧道，全部逐字节一致，UI 停止后 TUN 移除。另连续三轮从界面启动、停止，每轮均建立并移除 TUN，界面恢复到可连接状态。该设备检查验证普通启停；精确的并发竞态由上述模拟 Android/JNI 边界的可控测试验证。

专用模拟器的数据已恢复，完整退出、无快照冷启动后再次确认数据库和偏好文件与备份逐字节一致、SQLite 完整且无测试节点。模拟器和本轮参考服务已关闭。完整源码、APK、构建资源、修复前失败及修复后证据位于 `build/integration/h3-lifecycle-validation.json` 与 `build/integration/h3-lifecycle/`。本轮没有重新验收 arm64 真机、公网、Private DNS 或长期切网，前述发送方向动态 QPACK 和剩余报文差异仍存在。

## 独立测速的网络换代（2026-11-28）

未连接 VPN 的批量测速原先在整个并发批次内复用首次选中的 Android `Network`，Rust 的系统 DNS 上下文也只在创建批次时初始化。只要一个慢测速仍未结束，切网后加入的测速就可能继续绑定旧网络，或因 DNS 网络代次过期而失败。

Kotlin 现在每次测速入场都读取并发布当前物理网络。同批请求继续共享一个平台对象和监听；没有物理网络或当前默认是 VPN 时，先发布断网，再拒绝新测速，防止重叠请求继续创建旧网络连接。最后一个调用结束后关闭平台资源，下一批重新创建。该逻辑集中在 `StandaloneProbePlatforms`，由 `RustCore` 调用，没有新增 JNI 接口或独立监听线程。

Rust `StandaloneProbes` 比较网络代次和默认句柄；变化时取消并等待旧测速及其派生任务退出，再安装新的 DNS 上下文和任务生命周期。同一代次仍并发测速并共享 DNS 缓存。永久停止信号独立于可替换的网络代次，防止刷新途中停止后重新启动任务；调用方丢弃测速 future 也会释放挂起的 DNS 请求。更新由新测速入场触发，不是独立测速的实时切网订阅；测速超时不包含等待旧代清理的时间。

新增 5 项 Kotlin 边界测试覆盖共享资源、旧请求仍忙时换网、断网/VPN 拒绝及恢复、失败清理和监听注册失败。去掉网络发布的临时验证变体会稳定报出“新测速仍绑定旧网络”，修复版本通过。Rust 宿主 21 项检查通过，包含 6 项 DNS 回调、11 项宿主生命周期和 4 项平台 DNS 测试；新增场景在两个旧 DNS 测速仍挂起时换代成功，并验证刷新期间停止不会派发新请求。

设备测试还发现实际 App 测速配置存在名称碰撞：转换器把出口组和内部代理客户端都命名为 `proxy`，测速创建 selector 后报 `invalid or duplicate control name: proxy`。现在仅由出口组持有该标签，内部代理客户端由目录分配身份；App 的直连客户端继续保留独立名称，避免与内置 `DIRECT` 合并而丢失配置。修复前实际 APK 和新增宿主用例均复现失败。修复后使用 Android 文档格式的回归在服务启动前后分别完成代理与直连 HTTP 测速，62 项配置测试通过。

`testRustPlatform` 汇总已有 VPN 生命周期、DNS、连接归属和新增测速平台边界检查，已接入 CI；Rust 宿主回归也加入同一入口。没有引入旧版本兼容、迁移逻辑或依赖升级。

四个 arm64/x86_64 Debug 与 unsigned Release APK 已更新，JNI 签名及随包原生库一致性检查通过，原生库仍使用 `dev` profile。131 项 Kotlin 单元测试在本轮重新执行通过；最后一次只改 Rust 配置转换，复用同源码 Kotlin 测试结果。中途环境重启中断了一次 R8 构建，保留中断日志，后续完整构建成功；71 份依赖锁文件未变。

Android 35 x86_64 使用最终 APK 的真实平台类、配置生成器和 JNI 通过实际测速。测试以 shell UID 运行，保留同一 Kotlin 平台对象跨越 Wi-Fi 断开与恢复，网络句柄由 `432902426637` 变为 `437197393933`；恢复后和下一批请求均到达本地 HTTP 参考服务并成功返回。旧请求在断网时已自行失败，因此设备结果不冒充“旧请求一直挂起”的精确竞态证明。最终 APK 的 71 项配置检查通过，App 数据库和偏好设置在测试前后及完整冷启动后均逐字节相同。

已停止模拟器、参考服务、ADB 和内存监控，移除临时构建 swap。按本轮内存要求，设备验收改为 2 GiB guest、3 GiB 进程组上限；每半秒检查整机余量，低于 1.5 GiB 自动停止本轮模拟器。早期一次并行的其他项目编译造成整机压力，已停止当时的设备尝试并保留失败记录。最终验收模拟器峰值约 2.75 GiB，整机最低可用约 4.23 GiB，未发生 OOM；构建继续使用 5 GiB RAM / 1 GiB swap 上限。日志、源码与 APK 哈希、修复前失败及资源证据见 `build/integration/probe-handover-validation.json` 与 `build/integration/probe-handover/`。本轮未验证公网、Private DNS、蜂窝切换、arm64 真机或新 APK 的 UI/VPN 流量。

该轮还发现未启用目录的连接路径会把代理连接显示为 `DIRECT`。原内部客户端名称也没有参与这条路径，删除重复名称并未新增该行为。后续复查已通过真实代理连接复现并修复，见下一节。

## 原 App 功能对齐复查（2026-11-28）

在原仓库 `rust` 分支，由主代理和一位子代理对照 sing-box 基线复查 UI、设置、订阅、节点编辑、备份、系统入口和内核边界。首页已恢复单 IP、加粗卡片及点按刷新。没有新增协议、旧版兼容或依赖升级；71 份依赖锁文件与上轮一致。

- **连接详情**：普通 Android 会话没有控制目录，原规则说明只在有目录时捕获，导致代理连接被标成 `DIRECT`、所有规则显示为 `match all`。现在在规则编译前保留脱敏的匹配条件和出口标签，不因此额外创建客户端目录。Kotlin 显示实际出口标签，并把内部直连名称还原为 `direct`。
- **列表与流量内存**：恢复按新到旧显示最近 500 条连接，复制详情前先限制数量。流量采样独立累加活动和已关闭连接的计数，不再构造所有连接的详情、包名及 JSON。活动连接关闭后仍释放记录，没有增加连接历史缓存。
- **网络策略节点的保存与测速**：原测速文档关闭 `auto_detect_interface`，与节点已有的网络类型、策略和回退参数冲突，导致编辑保存或测速校验失败。测速文档现与 VPN 使用同样的物理网络策略；离线编辑校验不需要安装平台回调。真实 HTTP 主机用例覆盖服务启动前后、代理与直连，以及 Wi-Fi 回调拒绝后的 cellular 回退选择；回调模拟不冒充真实蜂窝切换。
- **错误日志**：Android 初始化恢复原版 error 级别。日志桥接明确传出严重级别，避免 Rust 带时间戳的 INFO/WARN 被 Kotlin 当作无前缀错误保存；每行 4096 字节、500 行及脱敏约束保留。

修复前的真实代理回归返回 `DIRECT`，修复后出口、匹配规则、排序、流量及独立关闭均通过。完整内核 2,904 项通过，60 项需要外部对端、环境或手动执行的检查默认跳过；700 条连接用例覆盖最近 500 条和完整计数。24 项 Android 原生主机检查、62 项配置检查、134 项 Kotlin 单元测试，以及全部 Kotlin 生命周期、DNS、连接归属和独立测速边界检查通过。连接/控制回归已加入统一 CI 入口。

完整测试编译首次因旧 WebSocket 夹具直接构造内部连接结构而失败，已改用现有测试 guard；随后无 swap 的编译触及 5 GiB cgroup 限制被终止，内核 OOM 日志保留，不能依据最后一次采样中的零 OOM 误报成功。保持 5 GiB RAM 硬限制，临时启用 1 GiB swap 后完整测试通过。本轮日志和构建材料位于 `build/integration/parity-review/`。

arm64、x86_64 的 Debug 和 unsigned Release 四个 APK 已更新。12 个 JNI 入口、8 个平台回调完整签名及随包原生库与构建库的 strip 后一致性检查通过；Rust 使用 `dev` profile，Release 完成 R8/资源压缩。完整 lint 为 0 错误、7 警告：5 条版本更新提示按用户要求不处理，另有动态 ABI 识别和恢复单 IP 后闲置的状态文案提示。Android 构建峰值 4.52 GiB，无 OOM。

Android 35 x86_64 使用最终 APK 的真实 Kotlin/JNI 通过 83 项配置检查。另在 shell UID 下运行完整代理、直连和测速链路：带网络策略的文档离线校验成功，未启动服务和服务运行中的 HTTP 测速分别为 535/548 ms；三次代理拨号均调用真实 Android `Network.bindSocket`，绑定当前 Wi-Fi 句柄 `432902426637`。代理、直连分别回显 14 字节，列表出口为 `proxy`、`direct`，匹配规则和最新排序正确；主动关闭代理连接后直连仍能继续收发。本轮没有建立 VPN 或操作 App 界面，不能替代真机或 VPN 流量验收。

首次设备功能检查通过后，另一个项目编译使整机余量低于 1.5 GiB，保护程序自动停止本轮模拟器。保留该次压力记录，待资源恢复后冷启动专用模拟器完成配置检查和数据核对；数据库、偏好文件均与测试前逐字节一致。最终模拟器峰值 2.75 GiB、整机最低可用 4.23 GiB，没有再次触发压力保护。模拟器、参考服务、ADB、监控及临时 swap 已清理，整机可用内存回到约 6.87 GiB。完整证据、源码和 APK 哈希见 `build/integration/parity-review-validation.json`。

本轮复查未再发现确定的产品功能删减，但不宣称全部平台和协议场景已完成验收。arm64 真机、真实蜂窝回退、Private DNS、长期切网及公网出口未在本轮重新验证；前文记录的 Naive/Chromium 剩余报文特征差异仍存在。

用户随后指出整套内核测试超出项目所需。默认 CI 已移除 shoes 控制目录、HTTP/2、HTTP/3、传输和 TLS 的整套库测试，仅保留 App 配置、Android 原生接口及 Kotlin 回归；协议专项按实际修改运行。上述 2,904 项是一次历史全量验证，不是后续开发门槛，不据此扩大产品范围。此次仅调整验证入口和说明，完成脚本语法检查，不重新编译或运行设备测试。

## 清理结果

独立 `/home/Code/core` 已在源码、构建和设备验证完成后删除，原 Git 提交及未合入实验源码保存在上述本地压缩交接材料。废弃的第一轮优化编译缓存也已清除。旧会话已通过会话工具归档；工具没有永久删除接口，未修改应用内部会话数据库。

按用户要求精简测试和冗余代码：删除重复的 `aerobox-cli`、桌面进程与特权网络测试、外网冒烟测试、压力/吞吐基准、App 未提供协议的独立集成用例，以及未接入的 ACME 服务端实现和测试。共清理 79 个文件、约 3.3 万行旧代码；协议互通夹具、路由与内存释放检查仍保留，`shoes` 命令仅作为这些互通用例的测试对端。同步删除无调用的 Android Rust 接口、Kotlin 状态方法、旧日志格式兼容及五种语言中的闲置文案，锁文件仅移除不可达依赖记录，没有升级任何保留版本。

清理后的 Rust 库和保留测试目标通过编译检查，Android 原生接口及受影响的生命周期/指纹用例也通过编译检查；Kotlin 编译和 4 项日志过滤、错误上下文与脱敏回归通过。检查时发现两处旧测试引用了废弃的加密 provider 路径，已改为当前实现。此次只执行上述 4 项测试，没有运行整套内核或外部对端测试，也没有构建 APK、启动模拟器。验证串行执行，最高观察到的内存峰值为 3.35 GiB，日志和删除清单位于 `build/cleanup/`。

## 协议裁剪与 APK 对比

继续移除 App 不提供的 WireGuard、Snell、Sudoku、XHTTP、ShadowTLS 实现与专属测试，提取 Naive 和 Vision/REALITY 仍需的共享代码。shoes 源码与测试净减 34,241 行，删除 gotatun，锁文件仅移除 17 项不可达依赖记录。Android 配置入口同时收紧为当前 App 文档与 VpnService 提供的 TUN 描述符。

11 项配置和 23 项 Android 边界回归通过，保留内核测试目标仅做编译检查。本轮构建单个使用 Rust release 优化的 arm64 Release APK，实测 14.12 MiB，原 sing-box 版为 21.24 MiB，减少 33.5%。R8 后 JNI、包内原生库一致性、16 KiB 对齐和规则内容检查通过。构建峰值 4.50 GiB，无 OOM、无 swap；没有执行设备验收。此前使用 dev 内核的旧 APK 与本次产物应分开看待，详见 [APK 体积与裁剪](apk-size.md)。
