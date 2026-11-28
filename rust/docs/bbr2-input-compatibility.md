# BBRv2与Android输入兼容

2026-11-23已完成主机验收和四ABI优化安装包。当前可用封存基线为
`target/android/app-bbr2-release/manifest.json`。以下验收状态以
`target/android/bbr2-input/`为准，不能由配置解析成功推断互通通过。

## BBRv2

新的`Bbr2Config`采用独立BBRv2模型、发送采样和窗口/带宽上下界；`bbr`继续选择BBRv1。
来源是固定Cloudflare quiche 0.24.6纯Rust实现，并按Android固定Naive/Chromium 150的
B2ON参数调整。具体来源、双BSD许可证与算法差异见
[vendor来源记录](../vendor/quinn-proto/src/congestion/bbr2/SOURCES.md)。

Quinn增加带默认空实现的包级回调，独立标识三个QUIC包空间中的发送。ACK批次包含
由该ACK触发的丢包和经Quinn验证的ECN；MTU探测不计入交付/丢包模型。密钥丢弃、
Retry、0-RTT拒绝、迁移和控制器替换会清理或隔离旧采样，既有控制器保留原回调。

字节计数使用u64，速率乘法用u128中间值；采样表仅存未决包，避免旧包长期挂起时
积累已完成空槽。默认最大窗口16 MiB，配置范围64 KiB..256 MiB，最小四个当前MTU。
ECN采用明确记录的保守beta响应，不声称TCP DCTCP/L4S或Cronet逐包调度等价。

原App在Naive QUIC提供`quic_congestion_control=bbr2`；固定sing-quic的TUIC只接受
cubic/new_reno/bbr，因此Rust共享工厂在原生TUIC接受bbr2属于扩展。

93项标准库独立测试通过（峰值约207 MiB），覆盖容量变化/丢包、真实pacing、
ProbeBW/ProbeRTT、ACK压缩/乱序、ECN、超过4 GiB及挂起旧包后10万次完成。
完整Quinn回归409项全部通过，包括新增三项连接测试和`SentPacket <= 128`检查。
首轮0-RTT测试夹具错误地移除缓存ALPN而仍期望发送早期数据；修正为保留旧ALPN、
让服务端选择新ALPN后真实拒绝，原流ID与发送窗口回收断言保留，生产规则未改。
Naive Go实际连接测试通过：真实连接使用BBRv2，plain/padded各两条隧道完成131,073字节回显与FIN；Android公共入口检查通过。

## Android输入

原App的`putStringOrArray`在单曲线时输出字符串；转换器现在把它归一为单元素
原生列表。无效、重复、空列表仍由原生策略拒绝。

固定sing-vmess对出站用户ID接受全部语法正确的UUID，包括非v4和nil值；其他
UTF-8字符串使用nil namespace的UUID v5。Rust客户端及普通TLS/REALITY的Vision
工厂已保持这一规则，严格的原生服务端UUID策略保留。名称按原始UTF-8字节计算，
不自行trim或Unicode归一化；SHA1来自既有纯Rust原语。

15组固定向量已对照独立Go库通过；普通VMess、旧认证VMess和VLESS的15组
真实认证与数据回环，以及公共Android检查测试已通过。

## 构建与分发

`bash scripts/test-quinn.sh`使用无默认C密码后端的RustCrypto测试提供者。后续
AAR将携带BBRv2的两个BSD通知与来源记录；封存脚本核对全部APK中的对应文件
哈希与AAR一致。正常产品依赖没有新增Go、C/C++密码库。

主机合并快照验收完成：2,866项内核回归、409项Quinn、40项配置、18项独立Go互通、
6项浏览器专项和21项Android主机测试均通过；41项需要外部环境的内核测试默认忽略，
上述18项互通已显式执行。活动产品依赖321项，无禁止密码后端。源码快照
`e5a5d8f5b24101f0aecd9b7a7086eccf38140534cff9f54ccdc8827a71d50e7d`。
四ABI优化构建、八个APK、138项JVM测试、R8/资源压缩/lintVital均已通过。后台首轮因缺失HOME导致两项临时目录测试失败，补齐真实
用户环境后完整重跑通过；保留失败记录。重跑峰值4,761,030,656字节，无swap/OOM。

发布记录（本地封存，未发布）：AAR SHA256
`512f8776afed8aa34508c7534d145306de5d34f9af9961e3bca9dc710d4de7cc`；
14个JNI入口、8个平台回调和全部Release DEX检查通过，八个APK均携带对应BBRv2许可证。
构建峰值4,719,869,952字节，受限swap峰值509,509,632字节，无内存限制/OOM事件。
Android11后续代码仍在独立stage，不包含在本次安装包；真机验收尚未进行。
