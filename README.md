# AeroBox for Android
[![API](https://img.shields.io/badge/API-31%2B-brightgreen.svg?style=flat)](https://android-arsenal.com/api?level=31) [![ci](https://github.com/imengying/AeroBoxForAndroid/actions/workflows/ci.yml/badge.svg)](https://github.com/imengying/AeroBoxForAndroid/actions/workflows/ci.yml) [![Releases](https://img.shields.io/github/v/release/imengying/AeroBoxForAndroid)](https://github.com/imengying/AeroBoxForAndroid/releases) [![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](./LICENSE)

AeroBox for Android combines a Rust 2024 proxy core with a native Kotlin Android app.

一款采用 Rust 2024 内核和 Kotlin 原生界面的 Android 通用代理软件。当前 `rust` 分支以原 sing-box 版本已有功能为整合范围，进度见 [Rust 开发说明](docs/rust.md)。

## 下载 / Downloads

- [GitHub Releases](https://github.com/imengying/AeroBoxForAndroid/releases)

## 功能 / Features

- 基于 Rust 内核的 Android VPN 模式代理
- 订阅管理、手动更新、自动更新
- 节点编辑、搜索、批量删除、复制到本地分组、JSON 导出
- 订阅、节点、设置和自定义规则的手动备份与合并恢复
- 分应用代理
- 路由模式切换：全局代理 / 规则分流 / 直连
- 使用官方 Geo 规则集
- DNS 自定义，支持 DNS over TLS / HTTPS
- IPv6 支持、开机自连、系统始终开启 VPN、断线自动重连
- 节点延迟测试、错误日志、按需连接详情、诊断导出、通知栏快捷切换
- Material 3 + Jetpack Compose 界面

## 支持的代理协议 / Supported Proxy Protocols

- Shadowsocks
- Shadowsocks 2022
- VMess
- VLESS
- Trojan
- AnyTLS
- Hysteria 2
- TUIC
- SOCKS5
- HTTP Proxy
- Naive

## 支持的订阅格式 / Supported Subscription Formats

- Clash / Clash.Meta YAML
- 常见 URI 节点订阅格式
- sing-box outbound JSON / 常见 JSON 节点列表
- 支持读取部分订阅流量与到期信息
- 支持本地、扫码和单节点导入

说明：

- 当前主要是导入节点信息
- 订阅中的分流规则等信息不会直接照搬进应用配置
- 远程订阅更新会覆盖节点编辑；需要保留的节点可复制到本地分组
- 备份包含明文凭据；恢复保留现有节点并添加备份中的副本，设置按备份恢复

## 系统要求 / Requirements

- Android 12+ (`minSdk 31`)
- 推荐使用 GitHub Actions 构建发布版本

## 本地开发 / Development

使用 JDK 25、Rust（版本见 `rust/rust-toolchain.toml`）、Android SDK 37.2 / Build Tools 37.0.0 和 NDK 30.0.16248370。
Gradle 9.8.2 由仓库中的 Wrapper 固定，并校验下载包 SHA-256。
Rust 源码与 Kotlin 桥接同仓库维护，Gradle 自动构建 JNI 库。

先安装 Rust Android targets，并按 `.github/scripts/prepare-geo-assets.sh` 准备规则资源，再运行：

```sh
python3 rust/scripts/run-bounded-build.py -- ./gradlew :app:testDebugUnitTest :app:lintRelease
python3 rust/scripts/run-bounded-build.py -- ./gradlew -PAEROBOX_ABIS=arm64-v8a :app:assembleDebug
```

统一构建入口限制进程组内存为 5 GiB，串行执行 Rust 和 Kotlin 构建。
详细约定与验证范围见 [docs/rust.md](docs/rust.md)。

## Credits

- Core: Rust runtime and vendored libraries in [rust/](rust/)
- Original Android core and external configuration formats: [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- Android runtime bridge: Kotlin / JNI
- UI & Android stack: AndroidX, Jetpack Compose, Room, WorkManager

## License

GPL-3.0-or-later

See [LICENSE](./LICENSE).
