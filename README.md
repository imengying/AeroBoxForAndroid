# AeroBox for Android
[![API](https://img.shields.io/badge/API-31%2B-brightgreen.svg?style=flat)](https://android-arsenal.com/api?level=31) [![ci](https://github.com/imengying/AeroBoxForAndroid/actions/workflows/ci.yml/badge.svg)](https://github.com/imengying/AeroBoxForAndroid/actions/workflows/ci.yml) [![Releases](https://img.shields.io/github/v/release/imengying/AeroBoxForAndroid)](https://github.com/imengying/AeroBoxForAndroid/releases) [![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](./LICENSE)

AeroBox for Android is a sing-box / libbox based proxy toolchain for Android.

一款基于 sing-box / libbox 的 Android 原生通用代理软件。

## 下载 / Downloads

- [GitHub Releases](https://github.com/imengying/AeroBoxForAndroid/releases)

## 功能 / Features

- 基于 sing-box / libbox 的 Android VPN 模式代理
- 订阅管理、手动更新、自动更新
- 分应用代理
- 路由模式切换：全局代理 / 规则分流 / 直连
- 使用官方 Geo 规则集
- DNS 自定义，支持 DNS over TLS / HTTPS
- IPv6 支持、开机自连、断线自动重连
- 节点延迟测试、运行日志、通知栏快捷切换
- Material 3 + Jetpack Compose 界面

## 支持的代理协议 / Supported Proxy Protocols

- Shadowsocks
- Shadowsocks 2022
- VMess
- VLESS
- Trojan
- Hysteria 2
- TUIC
- SOCKS
- HTTP Proxy

## 支持的订阅格式 / Supported Subscription Formats

- Clash / Clash.Meta YAML
- 常见 URI 节点订阅格式
- sing-box outbound JSON / 常见 JSON 节点列表
- 支持读取部分订阅流量与到期信息
- 支持本地、扫码和单节点导入

说明：

- 当前主要导入节点信息
- 订阅中的分流规则等信息不会直接照搬进应用配置

## 系统要求 / Requirements

- Android 12+ (`minSdk 31`)
- 推荐使用 GitHub Actions 构建发布版本

## Credits

- Core: [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- Android runtime bridge: `libbox` / `gomobile`
- UI & Android stack: AndroidX, Jetpack Compose, Room, WorkManager

## License

GPL-3.0-or-later

See [LICENSE](./LICENSE).

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=imengying/AeroBoxForAndroid&type=Date)](https://www.star-history.com/#imengying/AeroBoxForAndroid&Date)
