# AeroBox Android 的 Rust + Kotlin 接入

Android 开发目录为 `/home/Code/AeroBoxForAndroid`，直接在原仓库的 `rust` 分支开发。使用当前 Rust 接口；旧 `SingBoxNative`、V2Ray 统计门面、Go/libbox 构建及数据库/备份迁移代码已移除。

## 调用边界

| Kotlin 调用方 | Rust 桥接入口 |
| --- | --- |
| `RustCore.initialize` | `RustCoreNative.initialize(storage = …)`，初始化并提供版本状态 |
| `RustCore.checkConfig` | `RustCoreNative.checkConfig(config)`，配置校验 |
| `RustCore.urlTestOutbound` | `RustCoreNative.urlTestConfig(config, tag, url, timeout, platform)` |
| `AeroBoxVpnService.coreSession` | `RustVpnSession`，拥有 TUN、内核和网络监控生命周期 |
| `VpnTrafficMonitor` | `session.isRunning()` 与 `session.trafficCounters()`，进程内统计 |
| 连接页面 | `session.connectionSnapshot()` 与 `session.closeTrackedConnection(id)` |
| 服务日志协程 | `session.drainLogs(RuntimeLogBuffer::appendCore)` |

`ConfigGenerator.generateVpnConfig` 生成当前 Android 配置文档，Rust `aerobox-config` 负责严格转换和校验。App 不再生成 V2Ray API 监听端口；流量统计不依赖配置中的统计服务开关。SRS 和外部订阅数据格式的支持属于应用功能。

## 服务生命周期

初始化、配置检查、启停、测速和统计查询放在工作线程，不能阻塞主线程。一个进程同一时间只有一个 Rust 内核。

```kotlin
val metadata = RustCoreNative.initialize(
    storage = File(applicationContext.noBackupFilesDir, "rust-core"),
)
// physicalNetwork 来自同一网络的能力和链路回调。
val session = RustVpnSession(service, connectivity, physicalNetwork)
session.startOrReloadService(config, RustTunController.Applications(include = packages))
val totals = session.trafficCounters()
session.closeService()
session.close()
```

`RustTunController` 建立 TUN 并设置地址、MTU、路由、DNS 和分应用规则。Rust 复制传入的借用 FD，Kotlin 保留自己持有的 FD，直到服务停止后关闭。DNS 使用接口前缀内的下一地址；分应用设置忽略已卸载包名，非空白名单若没有任何有效应用则启动失败。

`startOrReloadService` 切换节点时重新建立 TUN、断开旧连接并重置会话流量。服务通过独立 IO 任务调用 `closeService`，可打断正在下载规则或启动的 Rust 调用。不要先等待启动持有的生命周期锁；Kotlin 协程取消本身不会中断同步 JNI。

## 网络、DNS 与测速

`DefaultNetworkMonitor` 只选非 VPN 物理网络。每轮注册独立维护 `PhysicalNetworkState`，等待能力与完整链路事件后发布快照，不在回调中同步读取 `ConnectivityManager`。初次启动最多异步等待 10 秒；用户停止可取消等待，超时进入服务错误清理。新 best 出现时先撤下旧网络，不依赖旧 best 一定收到 lost；旧网络迟到的事件被忽略。

默认网络变化调用 `session.networkChanged(snapshotOrNull)`。空快照立即禁止新的默认网络绑定；Android underlying-network 更新及 JNI 刷新在会话工作线程串行执行。`onNetworkRefreshFailure` 将异步错误交给服务重试流程。完整 `LinkProperties` 保留路由、MTU 和 Private DNS 等变化。

`VpnPlatformCallbacks` 先 `VpnService.protect(fd)`，再绑定物理 `Network`。多网络候选通过带代际的 `physicalNetworks()` 快照和 `protectOnNetwork()` 绑定；失效代际与消失网络明确失败。平台回调不得重入生命周期 JNI。

系统 DNS 由 `PlatformDnsQueries` 在指定物理网络上调用 `DnsResolver.rawQuery`，Rust 负责请求验证、缓存、截止时间和取消。完成回调只能调用单向 `completeDnsQuery`。网络失效或关闭时先移除查询，再取消平台任务，避免平台没有取消回调时挂住等待者。

节点测速复用当前 VPN 的平台对象；未连接时，`RustCore` 通过引用计数共享临时 `PhysicalNetworkCallbacks`，最后一个探测结束就关闭。启动或停止 Rust 会取消并等待独立探测，测速失败返回 UI 的失败结果，不影响节点保存。

## 流量、连接与缓存

`trafficCounters()` 返回当前会话的上传/下载字节，通知和界面按差值计算速度。停止轮询直接取消并等待协程，没有 gRPC 通道或关闭空实现。

Rust 持续保留有容量上限的活动连接统计。连接页面在可见且亮屏时读取快照，离开时由 Compose 生命周期停止轮询；无需切换内核跟踪状态。关闭连接使用快照的 `id`。

FakeIP 和远程规则缓存使用应用私有目录。默认目录在进入 Rust 前解析 Android 路径别名；显式路径仍接受 Rust 的严格校验。`checkConfig` 不打开端口或下载远程规则，报告 `deferredRemoteRules` 与 `requiresTunDescriptor`；远程内容在实际启动时验证。

## 构建与验收

Android Gradle 自动从本仓库 `rust/` 编译 JNI 库，平台 Kotlin 代码直接在 App 中编译；没有 AAR 依赖。构建说明见 [开发文档](../../docs/rust.md)。

已有模拟器 TUN、TCP/UDP、DNS、FakeIP、分应用、启停、HTTP/SOCKS 公网页面与短暂 Wi-Fi 中断结果，见 [DNS 与分应用](../docs/android-network-validation.md)、[网络切换](../docs/android-network-handover.md)。未验收协议、高级选项、真实蜂窝切换和 arm64 真机仍需逐项验证。
