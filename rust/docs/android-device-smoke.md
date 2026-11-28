# Android 模拟器实测与源码清理（2026-11-26）

本轮优先验证 App 能否启动 VPN 并传输数据，同时删除已废弃的接口、原型和重复构建目录。工程还在创建阶段，直接使用当前接口，不保留旧 API、schema 1 或 iOS 导出。

## 实际运行结果

使用现有 `AeroBox_AOSP35` x86_64 模拟器，安装 `/home/Code/AeroBoxForAndroid-rust` 生成的 Debug APK。现有 App 数据先做私有备份，单独导入本机测试节点 `Rust-Emulator-Smoke`，未使用已有代理节点。

首轮发现实际启动缺陷：`VpnPlatformCallbacks` 构造时及启动前的 `networkChanged` 会调用 `VpnService.setUnderlyingNetworks`，但当时 TUN 尚未建立，Android 返回失败。修复为初始网络交给 `VpnService.Builder`，TUN 和 Rust 启动成功后才调用服务更新；启动期间的网络变化在激活时统一补上。无物理网络时显式传空数组。

Android API 对建立前后的区分见 [VpnService.setUnderlyingNetworks](https://developer.android.com/reference/android/net/VpnService#setUnderlyingNetworks(android.net.Network[])) 与 [Builder.setUnderlyingNetworks](https://developer.android.com/reference/android/net/VpnService.Builder#setUnderlyingNetworks(android.net.Network[]))。

| 设备操作 | 观察结果 |
| --- | --- |
| VPN 关闭后请求测试地址 | 超时，不能直接取得响应 |
| App 启动 VPN | 建立 `tun0`，界面显示已连接 |
| Android shell 发起 HTTP 请求 | TUN → Rust → SOCKS 节点，返回 `AEROBOX_RUST_ANDROID_VPN_OK` |
| 连续两次停止、重启 | 停止关闭 TUN 且请求失败；每次重启后请求成功 |
| App 切到后台 | 同一 HTTP 请求成功 |
| 关闭 Wi-Fi，再连接 AndroidWifi | 断网时请求失败；App 自动重连后请求恢复 |
| 最后停止 | TUN 消失，请求超时；随后模拟器和临时节点均已关闭 |

测试节点由 [android-smoke-peer.py](../scripts/android-smoke-peer.py) 在主机 loopback 上提供，只接受目标 `203.0.113.10:18080` 并返回固定 HTTP 响应。它拒绝其他目标，因此截图中的公网探测“本次未连通”是此测试设置的预期结果。这证明了本机 TCP 出入路径，不证明真实互联网、DNS、UDP 或其他协议已完成设备验收。

短暂断网恢复经过 App 的自动重连流程，日志中保留了物理网络尚未恢复时的失败和重试。未做长时间离线、移动网络切换、耗电或泄漏压力测试。两轮启停后的文件描述符采样为 147 → 152 → 147，不能据此宣称不存在资源泄漏。

证据目录：[`target/android/emulator-smoke/`](../target/android/emulator-smoke/)。主要记录为 `http-baseline.json`、`http-connected.json`、`device-cycles.json`、`network-cycle.json`、`service-final.log`、`final-stop.json` 和 [连接截图](../target/android/emulator-smoke/connected-final.png)。

## 当轮产物与后续状态

当轮 x86_64 APK 的 SHA-256 为 `15f45356afb7ca032b544eeb8c3b250ae28d689a53d3b09233e74950dea249c0`，arm64 为 `99aafd38b47a5341635f562070933d83d06ce2a8bd1ddd0afb62191ec8c36607`。这两个桥接修复包和对应 AAR 已被后续 DNS/FakeIP 修复替代并删除；使用 [最新安装包与设备记录](android-network-validation.md)。旧哈希、构建与原生库一致性记录继续保留。

当轮 Kotlin 桥接编译、现有 5 项会话生命周期回归和 App Debug 构建通过。源码删除后的 Android x86_64 库、主机 CLI 编译及纯 Rust 活动依赖审计均通过；三个锁文件只删除旧条目，没有新增包或升级版本。编译仍有现存警告，未执行全库测试。记录在 [`target/cleanup-20261126/checks.json`](../target/cleanup-20261126/checks.json)。

## 删除内容与资源占用

删除各 crate 的重复 `target`、旧主机构建目录、36 份旧验证树和已封存 AAR 内的可再生 JNI 库副本。旧验证树先按内容去重压缩，并逐项核验后删除；压缩归档约 62 MiB。清理前后文件系统实际可用空间增加 **13.25 GiB**，不把目录逻辑大小当作实际释放量。清理后磁盘可用空间约 28 GiB。

源码删除 28 个文件、修改 23 个文件，净减少约 151 KiB：旧 shoes JNI/C/iOS 导出及专属测试、旧 Docker/release smoke 包装、schema 1 原型 crate 和 CLI 分支。现用 AeroBox JNI、平台回调和协议实现继续使用；现用主机平台 feature 改名为 `embedded-platform`，无旧名别名。直连示例改用当前配置格式。

清单、补丁和压缩源码备份均在 [`target/cleanup-20261126/`](../target/cleanup-20261126/)。后续缓存清理脚本仅处理本仓库，不再遍历其他工程。

构建和模拟器交替运行。源码清理验证内存峰值约 **2.22 GiB**，验证后已删除约 611 MiB 的临时 Cargo 目录。桥接/App 构建内存峰值约 **2.91 GiB**，模拟器进程组约 **2.75 GiB**，均无 OOM。运行中的 App PSS 采样约 **121–125 MiB**，原生堆初次采样约 15 MiB；这是本机简单 SOCKS 场景，不能外推为所有协议的内存上限。

下一步按 Android 功能矩阵验收真实出口、DNS/UDP、分应用和实际使用的协议组合。Naive Chromium 行为等尚未完成的实现继续单独标注，避免再用大量主机测试替代可安装、可观察的 App 结果。
