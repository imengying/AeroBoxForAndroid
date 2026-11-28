Android 的 `utls.fingerprint: "random"` 从固定的五个 TLS profile 中选择一个：Chrome133、Firefox120、Edge85、Safari16、Ios14。选择在进程第一次需要它时完成，同一进程的节点、普通 TLS、REALITY、配置检查、重连、reload 和核心 stop/start 都共用这个结果。新进程可以重新选择，但不保证每次选到不同项。它不包含 Android11、QQ、360 或 randomized，也不会因握手失败换一个模板。

这是 Android 的 TLS 指纹选项，不是新增浏览器或 iOS 客户端。所选 profile 的真实密码、身份验证、TLS 版本和扩展实现继续使用已有固定 profile。Chrome 自身的扩展 shuffle、每次握手的 random/session id 和私钥仍正常更新；固定选择不意味着复用 TLS 密钥或整份 ClientHello。

Android/sing-box 配置使用：

```json
{"tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"random"}}}
```

native 普通 TLS 在 `options.fingerprint` 使用 `"random"`，native REALITY 在其 `fingerprint` 字段使用 `"random"`。关闭 uTLS 时不会调用选择器。`randomized` 和 `360` 已分别实现，见 [randomized](randomized-fingerprint.md) 与 [360](browser360-integration.md)；不改变本选择器的五候选池。

选择以后，显式版本、完整套件顺序、group 顺序、ECH 和传输限制按所选 profile 检查；冲突会报错，不会删除候选、重抽或静默覆盖用户设置。例如 Firefox 的 REALITY 套件顺序为 AES128-GCM、ChaCha20-Poly1305、AES256-GCM，其他四种的顺序为 AES128-GCM、AES256-GCM、ChaCha20-Poly1305。真实 ECH 继续遵守已有 Chrome 政策，选到其他模板时不会为了 ECH 重抽 Chrome。QUIC/Naive 的 browser profile 限制保持。

原 sing-box v1.14.4 在 Go 包初始化时用 math/rand 选择五个候选。Rust 实现采用共享 `aerobox-fingerprint` crate 的 OS 熵，在第一次读取时一次选择；不模拟 Go 的全局随机序列或 GODEBUG 设置。选择与 TLS 私钥随机源分离。初始化错误会保存到进程结束并稳定返回，不会降级到默认模板。getrandom 仅调用操作系统随机接口，没有新增 C/C++ 密码后端。

配置解析 `random` 字段时就可能固定选择；完整配置随后出现语法错误或政策冲突，也不会重新选择。Android 转换结果和 native 反序列化结果保存的是**实际固定 profile**，再次序列化也输出该名称。需要新进程重新选择时，应保存原始包含 `random` 的用户配置；normalized/native 输出是本次解析快照，不是跨进程随机请求的替代品。

2026-11-25 已合入主源码。选择器开发/优化各5项、配置45项、原生策略5项、浏览器生产入口18项、内核2,881项、Android主机45项全部通过；内核另有50项依赖外部环境的测试默认忽略，相关浏览器互通已显式运行。四ABI的共享选择器源码检查与Android纯Rust依赖审计通过，Android依赖图确认转换器和协议运行时只链接同一个选择器crate。

生产 `random` 测试使用本次进程实际选择的模板，验证普通TLS、REALITY及错误认证后的选择稳定性；五种候选的策略通过确定性注入逐项检查，完整密码互通沿用已验固定模板。未改变的密码、Quinn及参考对端代码经哈希核对，继承Firefox的开发/优化各225项密码、409项Quinn和18项独立协议互通证据，不重复宣称本轮重跑。

本轮验证和合并记录位于 `target/random-production-stage/{validation,applied}.json`，原始主机快照与文档变更分别保存。后续360/randomized合并快照已统一重建，当前封存安装包为 `target/android/app-randomized-release/`，已包含本次random选择器。未完成真机VPN验收。
