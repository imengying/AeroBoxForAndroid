# APK 体积与裁剪

本轮在原仓库的 `rust` 分支完成裁剪，并构建单个 `arm64-v8a` unsigned Release APK。两版都经过 R8 和资源压缩，应用 ID、版本号、target SDK 和 ABI 一致；三个内置 SRS 规则集解压后的 SHA-256 完全一致。

| 构建产物 | APK | 包内内核库，解压后 |
| --- | ---: | ---: |
| 原 sing-box 版 | 21.24 MiB（22,270,241 字节） | 44.91 MiB |
| 此前 Rust 版，内核使用 dev profile | 19.65 MiB（20,602,636 字节） | 55.76 MiB |
| 本次 Rust 版，裁剪并启用 release 优化 | **14.12 MiB（14,807,884 字节）** | **23.03 MiB** |

当前 APK 比原版减少 **7.12 MiB，33.5%**，比此前 Rust 包减少 5.53 MiB。当前包内原生库压缩后约 9.83 MiB，DEX 约 3.91 MiB，其余主要为资源、规则和 ZIP 元数据。

这是实际构建产物的对比，不是单一变量实验：原版和当前版的内核、构建工具不同；此前 Rust 包还没有启用原生 release 优化。因此差值不能全部归因于本轮代码删除。测试本身不进入 APK，删测试主要减少维护与验证负担。库文件体积也不等于运行内存。

## 清理范围

- 删除 App 不提供的 WireGuard、Snell、Sudoku、XHTTP、ShadowTLS 实现、配置分支及专属测试。相对本轮快照，shoes 的 Rust 源码与测试净减 **34,241 行**；删除 56 个路径，提取 4 个共享模块文件。
- 删除仅由 WireGuard 使用的 `vendor/gotatun`，共 64 个文件。Android 和 shoes 锁文件各移除相同的 17 项不可达依赖记录，保留包没有新增或升级版本。移除无消费者的消息接口与计数器访问入口。
- Android 配置入口只接受当前 App 文档，删除原生配置数组旁路和按 Linux 设备名创建 TUN 的旁路。TUN 由 VpnService 提供描述符，减少重复处理。
- 已将 App 独立测试、shoes 的测试/夹具/示例及 Markdown 文档从 Gradle 原生库重建输入中排除；默认验证继续集中于 App 配置、Android 接口和 Kotlin，协议专项按实际修改运行。

Naive 所需的 HTTP/3 适配和 Vision/REALITY 所需的 TLS Hello 解析已提取为共享模块。原 App 的节点协议、SS 插件、TUN/IP/TCP 栈、DNS 和分流能力继续保留。用于协议互通的测试对端和密码库正确性用例仍有用途；没有按测试总数机械删除。历史协议文档与许可证保留并注明历史范围。

## 验证与边界

- 11 项受影响配置回归及 23 项 Android 边界回归通过，覆盖启动/停止、网络切换、DNS、测速、连接关闭和 TLS 配置。
- 保留的内核库及测试目标编译检查通过，没有执行全量内核测试。末尾无消费者接口的删除由最终 Android Release 编译验证。
- arm64 Release 构建成功，包含 Kotlin 编译、R8、资源压缩和 `lintVitalRelease`。本次完整构建耗时 23 分 2 秒；使用单个构建任务槽，内存峰值 **4.50 GiB**，5 GiB 硬上限，未使用 swap、未发生 OOM。
- R8 后 12 个 JNI 入口和 8 个平台回调的签名检查通过。包内内核与本次构建库去符号后 SHA-256 一致，ELF 和 ZIP 的 16 KiB 对齐检查通过；内核仅动态链接 `libdl.so`、`libm.so`、`libc.so`。
- 当前活动产品依赖未发现 Go/libbox、Cronet 或 C/C++ 密码后端。APK 中没有测试目录或旧 `libbox.so`。

本轮只更新 arm64 Release，其他 ABI 的旧产物不代表本次源码；没有启动模拟器或进行真机 VPN、运行内存实测。

## 产物与依据

- [当前 arm64 APK（未签名）](../app/build/outputs/apk/release/app-arm64-v8a-release-unsigned.apk)
- [逐项体积、规则及 SHA-256 对比](../build/size-review/comparison.json)
- [删除清单](../build/size-review/shoes-cleanup.json)、[依赖变化](../build/size-review/dependency-changes.json)
- [构建日志](../build/size-review/arm64-release.log)、[Android 边界回归](../build/size-review/android-boundary-tests.log)
- [JNI 检查](../build/size-review/apk-jni.json)、[原生库与对齐检查](../build/size-review/apk-native-audit.json)

原版来自 `main` 的 `b332fe831821147962e6ab869f08e92e9b159b9b`，使用保留在 `.codex/rust-return-20261127/main-app-build/` 的 sing-box 1.14.5 产物。此前 Rust 包已保存至 `build/size-review/apks/`，当前源码哈希保存在 `build/size-review/final-source-hashes.json`。

当前 APK SHA-256：`332c0daca8d7d0742fc9be5d2425e0065e8bc71b07b7c4b9218032afcd7740e4`。
