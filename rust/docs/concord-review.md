# Concord 源码对照

检查日期：2026-11-24（北京时间）。固定提交为
[`b3fab9e0fb81330c65bf62dea47caef845468747`](https://github.com/chen08209/concord/tree/b3fab9e0fb81330c65bf62dea47caef845468747)。
本轮下载约 20 MB 源码做只读检查，没有编译 Concord、复现性能测试或复制其实现到产品。
源码哈希、GitHub API 返回及审计范围保存在 `target/reference/concord-review/`。
其中 `tls-review.md` 另记录了 TLS 调用链、测试边界和 26 个所读文件的哈希。

Concord 是值得持续参考的 Rust 代理内核，协议实现、嵌入接口、测试和性能测量已有相当规模。
它的目标是 Clash/mihomo 兼容；本项目的目标是 AeroBox Android 固定的 sing-box 行为，且密码实现必须为 Rust。
这两项差异决定了它目前不能直接替代本项目的内核，也不能消除原始浏览器指纹和 Naive 的剩余工作。

本项目只开发 Android。下文的 `ios`/`safari` 是原 Android 节点编辑器提供的 TLS 指纹名称，
最终由 Android 内核发送对应 ClientHello；这里没有 iOS 客户端或 Apple 平台移植任务。

## 已核对的能力与边界

| 范围 | Concord 固定提交的实际情况 | 对 AeroBox 的意义 |
| --- | --- | --- |
| Rust 版本 | workspace edition 2024，rust-version 1.100，29 个成员 | 工具链方向一致；依赖边界需要另外核对 |
| 密码实现 | rustls/webpki/QUIC 使用 AWS-LC；浏览器 TLS 使用 boring/boring-sys/tokio-boring；WireGuard、SSH 也选择 AWS-LC | 不满足严格纯 Rust 密码要求；换 provider 还涉及直接调用与记录层，不能只改一个 Cargo feature |
| 协议 | SS、VMess、VLESS、Trojan、AnyTLS、HY2、TUIC、SOCKS、HTTP，以及 SSR、Snell、WireGuard、SSH、mieru、ShadowQUIC、MASQUE 等均有构造分支和实现 | 常用协议重合较多，它的范围还包含许多 AeroBox 当前没有的协议 |
| Naive | 配置类型与出站构造没有 Naive；相关源码搜索也未找到实现 | AeroBox 明确生成 `type=naive`，H2/H3、窗口、padding 等仍需我们实现和验证 |
| 普通 TLS 指纹 | Firefox/Safari/iOS/Android/360 映射 Chrome；Edge/QQ 映射 Chrome120，并返回警告 | 有模板名称不等于实际发送原始模板，不能替代我们的固定 uTLS 逐字节兼容 |
| 旧 TLS 与 CBC | BoringSSL 路径最低 TLS1.2；CBC 记录留在 BoringSSL 中处理 | 不能复用为纯 Rust TLS1.0/1.1、CBC、3DES 的完整实现 |
| REALITY | 自编码 ClientHello，保留独立模板；实际握手仅完成 TLS1.3 X25519/混合交换，拒绝 HRR 和 P-curve 选择 | 可参考认证、消息边界与拒绝用例；不能将其模板编码能力算作旧 TLS 完整握手 |
| Android | `libconcord.so` 提供 C ABI，宿主负责 JNI；有 protect、UID/package 回调；Android CI 覆盖 arm64、armv7、x86_64 | 可参考接口职责划分；AeroBox 仍需自己的 JNI/Kotlin、多网络绑定、系统 DNS 和四 ABI 接线 |

依据：
[workspace 与依赖](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/Cargo.toml#L40)、
[出站分派](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/proxy/src/build.rs#L24)、
[配置类型](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/config/src/proxy/parse.rs#L22)、
[实际指纹映射](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/tls/src/fingerprints.rs#L96)、
[REALITY 边界](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/docs/compatibility.md#L58)、
[Android 宿主接口](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/bins/android/src/platform.rs#L14)。

Concord 的 `random` 按进程缓存有权重的四家浏览器选择，`randomized` 又映射到 `random`。
我们的兼容基准仍为 Android 固定的 sing-box/uTLS，不能将不同项目的选取规则混用。
Concord 第三方清单也明确提到采用过 shoes 的协议代码；本项目同样基于本地维护的 shoes，
比较时应落实到具体路径和选项，不能只比较“Rust”或协议名称。
[随机选择](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/tls/src/fingerprints.rs#L63)、
[第三方来源](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/THIRD_PARTY_NOTICES.md)。

## 适合借鉴的工程实现

1. **所有后台任务都有生命周期归属。** `Tasks` 将 TaskTracker、取消令牌和 runtime handle 放在一个入口，
   引擎停机能等待任务结束。值得用其停止、配置替换和延迟清理场景补充我们的生命周期验收。
   [任务所有权](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/common/src/task.rs#L1)。
2. **缓冲区只在需要时占用，并限制缓存。** StreamBuffer 按大小复用、为封装预留头尾空间；每线程缓存最多 8 个，
   跨线程溢出池也有上限。relay 的双向状态机保留短写和半关闭，裸 TCP 还使用有界批量写。
   对我们最有价值的是“空闲连接内存、取消后回收、背压”的验证方式，具体大小须在本项目测量。
   [缓冲池](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/common/src/stream_buffer.rs#L11)、
   [转发状态机](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/net/src/relay.rs#L96)。
3. **QUIC 接收临时区按 poll 借用。** 它修改 Quinn，将临时接收内存从 endpoint 的整个生命周期移到线程缓存的短期借用，
   并检查重入时不同租借不能别名。我们的 Quinn 仍持有每 endpoint 接收区；频繁建连和关闭等待期值得单独测量。
   这只是待验证优化候选，当前尚未移植或声称节省多少内存。
   [实现与回归](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/vendor/quinn/src/endpoint/recv_buffer.rs#L1)。
4. **统一 socket 入口和公开兼容差异。** Sockets 集中 protect、接口绑定、FD 压力判断；配置分层和测试明确哪些输入生效。
   AeroBox 已有自己的失败策略，应借鉴覆盖方法，保留我们对显式不支持设置的报错行为。
   [socket 入口](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/net/src/sockets.rs#L21)、
   [配置分层测试](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/config/tests/tiers.rs)。
5. **独立对端、分配与空闲负载测试。** 互操作使用独立 mihomo/Xray 等进程，CI 为下载对端固定哈希；
   TUN 有 10,000 个空闲流的内存测量和分配测试。我们可以按相同的工作负载测本项目，
   避免把另一个内核的性能结果直接当作自己的结果。
   [互操作入口](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/proxy/tests/interop.rs#L6)、
   [空闲流测量](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/crates/tun/tests/idle.rs#L25)。

## 成熟度证据

本轮统计源码有 850 个自有 Rust 文件、约 26.2 万行，包含测试，不含 vendor；数量只能说明规模。
GitHub API 显示仓库创建于 2026-10-30，查询时 main 历史有 239 次提交，存在 `v0.1.0-pre.1` 标签，
Releases API 列表为空。公开仓库创建时间不能代表作者实际开始开发的时间。

固定提交的 [CI 运行](https://github.com/chen08209/concord/actions/runs/45178205216) 中，
Linux Test、Interop、Release、Lint、三个 Android 目标及 Windows clippy 成功；macOS 的 Run tests 失败，
公开注释只有 exit 101，本轮没有确定根因，不能据此推断全部平台不可用，也不能写成 CI 全绿。

性能文档包含 Linux/macOS 回环测量、Android 小米 11 上的 VPN 直连测试及模拟器测试。
作者报告手机冷启动 PSS 为 30.0 MiB，对照 Go 核心为 66.4 MiB；该手机测试是 direct，
不代表所有代理协议的内存或吞吐，也没有在本服务器复现。
其测试方法包括交替顺序、独立进程和多轮测量，适合作为我们的性能验收参考。
[性能报告与方法](https://github.com/chen08209/concord/blob/b3fab9e0fb81330c65bf62dea47caef845468747/docs/performance.md)。

Concord 声明 GPL-3.0-or-later，并维护第三方来源清单。本轮仅记录行为和设计，未导入其代码。
下一步继续完成纯 Rust 浏览器兼容与 Naive，对缓冲区、QUIC endpoint 和生命周期优化先做本项目测量，再决定具体改动。
