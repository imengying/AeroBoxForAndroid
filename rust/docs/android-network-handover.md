# Android 切网与实际代理出口（2026-11-26）

本轮改动已生成 APK 并在 Android 35 x86_64 模拟器验证。修改的是 Android 平台桥接和 App 的网络监控；Rust 协议库沿用已封存的优化内核，没有重编 Rust 或改变密码依赖。

## 行为改动

`DefaultNetworkMonitor` 原来在收到网络事件时同步读取网络能力、链路数据，并立即用于 socket 绑定。Android 明确说明该同步视图可能落后于回调，应使用能力与链路回调的参数：[NetworkCallback.onAvailable 文档](https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback#onAvailable(android.net.Network))。

现在 `PhysicalNetworkState` 等同一网络的两类事件齐全后发布不可变快照，保留整个 `LinkProperties` 的路由、MTU、DNS 等信息。新 best 网络出现时撤下旧网络，不依赖旧网络一定收到 `onLost`；旧网络迟到的事件被忽略。`VpnPlatformCallbacks` 使用快照做默认绑定和读取 DNS，断网立即禁止新连接使用旧的默认绑定。Android underlying network 更新与 JNI 刷新在会话工作线程中串行执行，网络回调只发布数据和排队。

启动时最多异步等待物理网络 10 秒，等待不阻塞 Android 回调线程。用户停止可取消等待；超时作为普通启动错误报告，进入现有清理流程，避免被当作用户取消后遗漏服务清理。不保留旧参数 API 的兼容层。

## 实际验证

证据在 [`target/android/exit-smoke/`](../target/android/exit-smoke/)。节点只在主机 loopback 上运行；模拟器通过 `10.0.2.2` 访问。`scripts/android-smoke-peer.py --public-example` 仅额外放行 `example.com:80`，使用保留地址的 DNS 映射，强制这次网页请求经过 Rust 代理路径。

| 场景 | 结果与证据 |
| --- | --- |
| HTTP CONNECT + Basic 认证，规则模式 | 固定标记及真实 `example.com` 页面均 HTTP 200；`http-public-final.json` |
| HTTP 错误密码 | VPN 已建立，代理记录认证拒绝，目标标记未返回；`http-bad-auth-final.json` |
| 关闭 App 自动重连，断开并恢复 Wi-Fi | 断网时请求失败，TUN 一直存在；恢复后标记和真实网页成功，期间无 VPN 重新启动日志；`network-final.json`、`handover-summary.json`、`http-after-handover.json` |
| 离线启动，等待中点击停止 | 约 3.71 秒内服务退出，没有 TUN 或崩溃；`offline-cancel.json` |
| 离线启动，等待网络超时 | 报告 10 秒无网络错误，约 11.53 秒时确认服务已退出且无 TUN；`offline-timeout.json` |
| 超时后网络恢复，重新点击连接 | 能重新建立 VPN 并访问真实网页；`http-after-offline-start.json` |
| SOCKS，启用 FakeIP、IPv6 | 标记和真实网页均成功；`socks-public-fakeip-final.json` |
| IPv4 / IPv6 FakeIP 地址 | DNS 返回两类 FakeIP，通过它们访问固定 HTTP 目标成功；`fakeip-final.json` |

规则模式关闭了 Geo 与自定义规则，仅保留基础规则与 QUIC 阻断设置，因此不将它当作完整规则库验收。公网仅验证普通 HTTP 页面，不包含 TLS、其他协议、Private DNS、真实蜂窝切换或 arm64 设备。截图中 App 自带网络检测目标未被临时节点放行，显示未连通不代表上表的实际网页请求失败。

修复前 APK 在同一短暂 Wi-Fi 中断场景也能恢复，**没有在设备上复现同步查询竞态**。该缺陷依据 Android API 约定修复，针对事件顺序的 JVM 检查通过；设备结果证明正常切网和退出行为。超时后的第一次自动点击未触发服务启动（没有新增服务日志），再次点击成功，该次脚本尝试不计为成功启动。

`verify-kotlin.sh`、App `assembleDebug` 和现有生命周期检查通过。生命周期检查共 10 项，编译真实 session/platform/state，覆盖不完整事件、旧 best 迟到、完整链路拷贝、忙碌时断网立即生效、底层网络设置失败的异步上报。Android/JNI 边界在这些 JVM 检查中是替代实现，设备验证独立完成。

## 安装包和资源

本轮 APK/AAR 后续已由 `rust` 分支版本替代并清理，当前下载见 [rust 分支记录](android-rust-branch.md)。下面保留当时受测产物的身份：

- x86_64 Debug APK SHA-256：`ae0dd6bb7b291d8361a57375dd48116fd66dd7744e22844d41902785d21d7901`。
- arm64-v8a Debug APK SHA-256：`a5c47d9f6495727df3198a666c4be8462c712db5df86c33fa825d9211943c11f`，当时未在 arm64 设备运行。
- [HTTP 连接截图](../target/android/exit-smoke/connected.png)、[SOCKS/FakeIP 连接截图](../target/android/exit-smoke/connected-fakeip.png)。

APK 原生库与 `app-randomized-release` 快照逐字节核对一致；前轮 Rust 源码清理没有重新构建入本 APK。构建内存峰值约 2.88 GiB，模拟器进程组峰值约 2.88 GiB，两者错开运行且均无 OOM。App PSS 单次采样约 120 MiB，不代表所有场景上限。

临时设置和节点数据库已恢复并核对，TUN、模拟器、临时代理已关闭；私有数据库副本已删除，见 `restored.json`。旧 `network-smoke` APK/AAR 已清理，仅保留历史证据和哈希。后续仍需逐项推进 Android 实际使用的剩余协议与功能验收。
