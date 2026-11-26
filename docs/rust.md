# rust 分支开发

直接在原 Android 仓库 `/home/Code/AeroBoxForAndroid` 的 `rust` 分支开发。内核使用已有 `/home/Code/core`，不创建额外 Android 仓库或工作目录。

Kotlin 负责界面、订阅、配置、VpnService、系统网络和 JNI；Rust 2024 负责协议、TUN 数据处理和密码实现。`RustCore` 管理初始化、配置检查和测速，`AeroBoxVpnService` 持有 `RustVpnSession`。流量直接读取会话计数，不通过本地 V2Ray/gRPC 端口；连接页面由自身生命周期控制轮询。

此分支只使用当前接口，移除了旧内核门面、Go/libbox 构建、数据库和备份迁移。当前数据库 schema 与备份恢复仍然保留；不自动迁移或清空旧数据库。Clash、节点 URI、sing-box outbound JSON 与 SRS 属于外部数据格式功能，会继续支持。

已有 AAR 时，在本机运行：

```sh
cd /home/Code/core
JAVA_HOME=/opt/jdk-25 python3 scripts/run-bounded-build.py -- \
  /opt/gradle-9.8.2/bin/gradle -p /home/Code/AeroBoxForAndroid \
  --no-daemon --max-workers=1 -Pkotlin.compiler.execution.strategy=in-process \
  -PAEROBOX_CORE_AAR=/home/Code/core/target/android/aerobox-core.aar \
  :app:assembleDebug
```

AAR 可通过 Gradle 属性或同名环境变量 `AEROBOX_CORE_AAR` 指定；默认使用相邻 `core/target/android/aerobox-core.aar`，缺失时明确报错。需要重建 Rust 时，在 core 目录使用统一内存限制入口运行 `bash android/build-aar.sh`，不在普通 App 调整时重复编译所有 ABI。构建与模拟器错开运行。

CI 的 Rust 来源、固定提交、SDK 和签名配置见 [BUILDING.md](../.github/BUILDING.md)。内核当前没有远程地址，因此云端构建需要先配置可检出的实际内核仓库；本地构建直接使用现有源码与 AAR。

已验收范围和剩余协议目标以 core 仓库的 README 与设备记录为准，不将配置可生成或 App 可编译等同于所有协议完成。
