# Rust + Kotlin 开发

在原 Android 仓库的 `rust` 分支开发。Rust 源码位于 `rust/`，Kotlin 平台桥接位于 `app/src/main/kotlin/com/aerobox/core/native/`，由同一次提交维护。工程不再依赖相邻 `core` 仓库、外部 AAR 或单独的内核仓库变量。

## 功能范围

以原 sing-box App 的 `ProxyNode`、节点编辑器及 `ConfigGenerator`、`OutboundConfigBuilder`、`DnsConfigBuilder`、`RouteConfigBuilder` 为准。保留其 11 种节点类型、已有传输与 TLS 选项、DNS/FakeIP、SRS 与自定义规则、分应用、测速、连接管理、日志、流量、备份和订阅。原 App 拒绝的 ShadowTLS、不提供的协议和服务器功能不作为新增目标。

按全新项目维护，只使用当前接口与配置。实现以简洁、高效为准，不增加旧版本兼容、历史数据迁移、版本升级流程或无关的依赖升级。

Kotlin 负责界面、订阅、配置、VpnService、TUN 建立和系统网络回调；Rust 2024 负责协议、TUN 数据处理及密码运算。`RustCore` 管理初始化、配置检查和测速，`AeroBoxVpnService` 持有 `RustVpnSession`。会话直接提供流量、连接和日志，平台回调通过 JNI 接入。原生函数及回调的 R8 保留规则在 `app/proguard-rules.pro`。

外部节点 URI、Clash/sing-box JSON 和 SRS 仍是支持的数据格式。当前配置转换会拒绝未知字段，不能通过忽略字段来声称实现功能。数据库和备份仍使用当前 schema；旧内核 API 和版本迁移层不属于此开发分支。

Android 配置在 Rust 侧只经过一次 JSON 解析，再直接转换为运行时结构。App 不接受原型 `schema_version`、原生配置数组、混入的 `native` 配置或已废弃的 `experimental.v2ray_api`；启动、切换节点与测速只保留实际使用的 JNI 入口。TUN 由 Android VpnService 创建并传入文件描述符，配置层不再提供按 Linux 设备名创建 TUN 的旁路。

## 构建

使用 JDK 25、Android SDK 37.2 / Build Tools 37.0.0、NDK 30.0.16248370 和 Gradle Wrapper 9.8.2。Rust 版本固定在 `rust/rust-toolchain.toml`。首次安装所需 Rust Android targets，并按 `.github/scripts/prepare-geo-assets.sh` 准备规则集。

在仓库根目录执行：

```sh
# JVM 回归只编译 Kotlin，不构建 Rust。
python3 rust/scripts/run-bounded-build.py -- ./gradlew --no-daemon --max-workers=1 :app:testDebugUnitTest

# 按需构建模拟器 APK；普通 Kotlin 修改复用未变化的 Rust 库。
python3 rust/scripts/run-bounded-build.py -- ./gradlew --no-daemon --max-workers=1 \
  -PAEROBOX_ABIS=x86_64 :app:assembleDebug

# arm64 真机 APK。
python3 rust/scripts/run-bounded-build.py -- ./gradlew --no-daemon --max-workers=1 \
  -PAEROBOX_ABIS=arm64-v8a :app:assembleDebug

# 默认构建原 App 的全部四个 ABI。
python3 rust/scripts/run-bounded-build.py -- ./gradlew --no-daemon --max-workers=1 :app:assembleRelease
```

`buildRustNative` 自动调用 Cargo、检查纯 Rust 依赖和动态链接库，并把原生库交给 AGP。Cargo 缓存位于 `rust/target/android-cargo/`，生成的 JNI 库位于 `app/build/generated/rust/jniLibs/`。Kotlin 桥接直接参与 App 编译和 R8，不再打包、解包 AAR。`AEROBOX_ABIS` 可用逗号指定 ABI；Rust 默认 `release`，本地调试可用 `-PAEROBOX_RUST_PROFILE=dev`。

Linux 构建入口串行执行并限制内存为 5 GiB、swap 为 1 GiB；需要 systemd scope 权限。构建和模拟器错开运行。CI 使用同一 Gradle 任务，不需要 `AEROBOX_CORE_REPOSITORY`、`AEROBOX_CORE_REF` 或内核访问 token；详见 [BUILDING.md](../.github/BUILDING.md)。

## 验证范围

默认 CI 仅运行 App 配置、Android 原生接口及 Kotlin 回归。日常开发按实际修改点验证：页面或文案调整做必要编译检查，连接和配置逻辑运行相关回归，修改协议时才运行对应专项。通过后不重复扩大测试，不因小改动重跑全部协议、全部 ABI 或模拟器验收。

`vendor/shoes`、HTTP/2、HTTP/3 等底层库的整套测试不作为默认门槛。即使只过滤某个模块，`cargo test --lib` 仍需编译整个内核测试程序；不要用它验证普通 App 改动。历史测试数量不代表产品功能范围，也不作为继续扩展功能的依据。

已清除重复的宿主 CLI、桌面进程管理/特权网络测试、外网冒烟测试、压力与吞吐基准，以及 App 不支持的协议集成用例。保留 App 边界、实际协议、路由和内存释放检查。底层 `shoes` 可执行程序仍供协议互通用例充当测试对端；Android 只使用嵌入式库。测试目录、构建清单和锁文件同步维护，清理不升级依赖。

WireGuard、Snell、Sudoku、XHTTP 和 ShadowTLS 的协议实现、配置分支、专属测试及 WireGuard 依赖已从内核移除。Naive 使用的 HTTP/3 流适配、Vision 使用的 TLS Hello 解析已移至共享模块；VPN 的 IP/TCP 栈、原有 TLS 指纹和 Shadowsocks 插件继续保留。独立测试及夹具不触发 Gradle 的 Android 原生库重建。

裁剪后 arm64 Release APK 为 14.12 MiB，原 sing-box 版为 21.24 MiB；对比口径、实际清理范围和验证边界见 [APK 体积与裁剪](apk-size.md)。

## 接续状态

独立 core 的会话决策和源码来源见 [整合记录](rust-integration.md)。`rust/docs/` 保留迁移过程中的协议及设备记录，旧目录和旧安装包路径仅用于历史溯源。以当前构建及实际验证结果判断交付范围，不将配置可生成或 App 可编译视为全部协议已验收。
