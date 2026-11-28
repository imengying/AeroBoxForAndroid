# Android DNS、FakeIP 与分应用实测（2026-11-26）

本轮修复三个会影响 App 实际使用的问题，并在现有 Android 35 x86_64 模拟器中验证。Rust 协议库没有重新编译；改动位于 Android 平台桥接，密码依赖边界不变。

## 修复

1. **系统 DNS 请求未进入 TUN。** 原来把 DNS 设为接口自身的 `172.19.0.1`，系统 local 路由直接接收请求，Rust 收不到包。实测 UDP 无回应、TCP 连接拒绝；同一内核向 `172.19.0.2` 查询可成功。`RustTunController` 现使用同前缀下一地址，IPv6 同样改为 `fdfe:dcba:9876::2`。地址越界、广播或撞上接口地址时明确拒绝，不使用公网地址兜底。
2. **FakeIP 开启后缓存初始化失败。** App 的挂载命名空间里 `/data/user/0` 是指向 `/data/data` 的符号链接，Rust 缓存的逐级禁止跟随链接检查返回 `Not a directory`。`RustCoreNative.prepareConfig` 现将系统提供的默认私有目录转为 `canonicalFile`；显式配置路径及 Rust 文件校验保持原语义。
3. **分应用设置残留已卸载包名。** Builder 添加应用时仅忽略 `NameNotFoundException`，其他平台异常继续报告。非空白名单若没有任何有效应用则明确失败，避免退化为代理全部应用。

源码为 [RustTunController.kt](../android/src/main/kotlin/com/aerobox/core/native/RustTunController.kt) 与 [RustCoreNative.kt](../android/src/main/kotlin/com/aerobox/core/native/RustCoreNative.kt)。设备前后证据集中在 [`target/android/network-smoke/`](../target/android/network-smoke/)，包括 `dns-alternate-address.json`、`cache-namespace.json` 和 `fakeip-start.log`。

## 设备结果

| 操作 | 结果与证据 |
| --- | --- |
| 关闭 FakeIP，TUN UDP/TCP DNS 查询 | 返回本机 DNS 对端提供的真实测试地址；`fixed-real-dns.json` |
| Android 系统解析域名后发 HTTP | 返回固定 HTTP 标记，Rust 代理路径成功 |
| SOCKS UDP，32/1400 字节 | 逐字节回包一致 |
| 开启节点 `udp_fragment`，4096 字节 UDP | 单个对端接收包为 4096 字节，回包一致；`udp-fragment-4096.json` |
| 开启 FakeIP 与 IPv6 | VPN 建立，系统 DNS 为 `.2` 和 `::2`；IPv4 查询返回 `198.18.0.0/15` 地址，并能通过该地址访问 HTTP |
| 经 IPv6 DNS 地址查询 A/AAAA | 成功；通过得到的 IPv6 FakeIP 地址访问 HTTP 成功；`dns-ipv6-final.json` |
| 停止 VPN，终止进程，再启动 | 同一域名保留相同 FakeIP，HTTP 仍成功；`fakeip-persistence.json` |
| 黑名单排除 shell | shell 请求失败，App UID 请求成功；`blacklist-shell-final.json` |
| 白名单包含 shell | shell 和 App UID 请求均成功；`whitelist-shell-final.json` |
| 白名单仅 App，以及已卸载包名 | shell 失败，App 成功；`whitelist-app-only.json`。这些分应用组合均包含一个不存在的包名，VPN 正常启动 |

最终 `service-final.log` 没有记录启动异常。`fakeip-fragment-final.json` 的 8192 字节输入被 Android `nc` 拆成两个 4096 字节数据报，因此不将它当作单个 8192 字节 UDP 包的通过证据。UDP 工具由外层限时退出，退出码 124 本身不表示收发失败；结果根据实际收到的 DNS 消息或载荷判断。

测试对端只在主机 loopback 上提供 SOCKS、UDP echo 和 `*.smoke.invalid` 的 DNS 响应，不访问公网。公网探测显示未连通是此设置的预期结果。以上证明本机路径；真实互联网、其他代理协议、Private DNS、真实 IPv6 出口、长时间运行和 arm64 设备仍需验收。首次 DNS/分应用检查使用缓存路径修复前的 APK，最终 APK 复验了 FakeIP、重启恢复、IPv6 和分应用黑白名单；两次构建间 `RustTunController` 源码相同。

## 安装包与资源

本轮旧 APK/AAR 已由后续切网修复版本替代并清理，当前下载见 [切网验证记录](android-network-handover.md)。以下仅保留当时的二进制身份，不将后续构建冒充本轮受测版本：

- x86_64 Debug APK SHA-256：`e85be53fd75c7978ebbc439912ee5375df39211eecbfb3cc29cf376f992af46e`。
- arm64-v8a Debug APK SHA-256：`c5669c55245ccf42effba435221f8d92b1d4f4b97443f5805226690a642fef94`；当时尚未在 arm64 设备运行。
- [本轮运行截图](../target/android/network-smoke/connected.png)继续保留。

两次 Kotlin/App 构建通过，原生库与原封存优化版本逐字节核对一致。没有新增 Rust 构建树或全库测试副本。构建内存峰值分别约 2.82、2.52 GiB；最终模拟器进程组峰值约 2.88 GiB，均无 OOM。App PSS 采样约 124 MiB，不是所有场景的上限。

临时 DNS/FakeIP/分应用设置和测试节点修改均已恢复，TUN 已关闭，模拟器与临时对端已停止，见 `restored.json`。ADB 临时 root 仅用于只读查看应用挂载路径，随后恢复普通用户。恢复完成后删除临时数据库副本和已被本轮替代的旧桥接 APK/AAR，保留结果与哈希记录。

后续已完成实际 HTTP 网页出口和网络回调修复，见 [切网验证记录](android-network-handover.md)。此处保留本轮结果；此前静态检查提出的同步查询竞态未在设备上复现，后续通过事件顺序测试验证修复，并在设备上确认正常切网行为。
