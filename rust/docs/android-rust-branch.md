# Android 原仓库 rust 分支（2026-11-26）

当前开发位置是原项目 `/home/Code/AeroBoxForAndroid`，分支为 `rust`。之前的额外 worktree 已移除；适配改动迁回原目录前后逐文件核对，原目录已有的 README 修改原样保留，未纳入本轮提交。原 `main` 分支没有推进。

## 本轮适配

- `RustCore` 负责应用初始化、配置校验和测速；删除 `SingBoxNative` 旧名称与统计门面。
- `AeroBoxVpnService` 直接持有 `RustVpnSession` 并读取会话流量；不再生成 V2Ray/gRPC 端口，也没有无作用的关闭接口。
- 连接页面通过自身生命周期停止轮询，移除旧跟踪开关。设置页与日志显示 Rust 内核。
- 删除 Go/libbox 专属构建脚本、补丁和导出源码，CI 使用 Rust AAR。云端内核仓库和固定提交需显式配置；本地使用现有 `core` 目录。
- 删除旧数据库/备份迁移及对应测试，保留当前 schema、备份恢复、订阅和 SRS 数据格式功能。

## 验证

在原 Android 目录完成 `assembleDebug`；16 项现有配置、流量、备份 JVM 检查通过，10 项桥接生命周期检查通过。没有新增测试矩阵或重新编译 Rust。CI 的 shell/YAML 静态检查通过，尚未运行在线 CI。

Android 35 x86_64 模拟器安装新 APK 后建立 VPN，开启 FakeIP/IPv6 经 SOCKS 访问固定标记和真实 `example.com:80`，均返回 HTTP 200。界面显示上传 `112B`、下载 `1.02KB`，设置显示 `1.0.0 (Rust 0.1.0)`，从 UI 停止后 TUN 消失。设备首次启动时 System UI ANR 弹窗阻挡点击，关闭弹窗后完成验证；未将未触发服务的脚本尝试算作成功。

证据位于 [`target/android/rust-branch/`](../target/android/rust-branch/)，包括 `unit-tests.json`、`apk-runtime-identity.json`、`device-summary.json`、`traffic-ui.json`、`service-final.log`。APK DEX 中没有 `SingBoxNative` 或 libbox 类，原生 Rust 库与此前封存版本哈希一致。AndroidX 的系统支持库仍属于 UI 依赖，不是密码后端。

- [x86_64 Debug APK](../target/android/rust-branch/app-x86_64-rust-debug.apk)：SHA-256 `ef2fcf9e20da017d8485f9951bdc676128e2e9815238281c8286a0f0a74f5c41`。
- [arm64-v8a Debug APK](../target/android/rust-branch/app-arm64-v8a-rust-debug.apk)：SHA-256 `e2030ee88d3e64900ec46c3bfee514b4770136e22f5c1d03d4df3b42ec78e224`，尚未在 arm64 设备运行。
- [四 ABI AAR](../target/android/rust-branch/aerobox-core-rust.aar)，默认 `target/android/aerobox-core.aar` 与其为同一文件的硬链接。
- [连接与流量截图](../target/android/rust-branch/connected.png)、[Rust 版本截图](../target/android/rust-branch/about.png)。

构建峰值约 3.15 GiB，模拟器进程组峰值约 2.88 GiB，错开运行且无 OOM。关闭模拟器和临时节点后，原设置及数据库均已恢复，临时私有数据库副本已删除。清除了额外 worktree 约 1.2 GiB 构建缓存，以及旧 Go 产物和重复 APK/AAR 约 448 MiB；保留当前安装包、必要构建缓存及验证记录。

本轮只验证 Kotlin 接入与已有内核运行路径，其他协议、TLS 出口、完整规则、Private DNS 和 arm64 设备仍按实际功能继续验收。
