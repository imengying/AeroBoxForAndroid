# Chrome133 配置接入

2026-11-23：已把受控 ClientHello 构造、ALPS、Brotli、独立 key share 和 TLS1.2
安全重协商接到实际出站配置。40项配置测试、6项生产模块专项（独立对端24种组合）、
开发/优化各75项密码测试、2,863项完整内核回归和16项独立协议互通通过。接线验证记录位于
`target/chrome-integration-stage/`；完整回归与构建记录位于
`target/android/chrome133/`。Android公共检查接口1项测试通过，覆盖Chrome开/关×普通TLS/REALITY×Vision的8种有效组合和冲突拒绝；纯Rust依赖审计通过。四ABI优化release AAR和八个APK已封存于`target/android/app-chrome133-release/`，138项JVM测试、R8/资源压缩/lintVital、JNI/DEX与ELF审计通过。AAR SHA256为`422f113ee2c10754105b16a31154ece37469948455bc51e47e2af310cff6c143`。上一个基础快照的
2,860 项内核回归和 16 项独立互通已通过，
其原生构建被主机重启中断，不计为新安装包验收通过。

## 配置

Android/sing-box 输入：

```json
"tls": {
  "enabled": true,
  "server_name": "proxy.example",
  "utls": {"enabled": true, "fingerprint": "chrome"}
}
```

固定基准为原 App 的 sing-box `v1.14.4`（提交 `c005f35300ce76427dc285481ec5695f5b179cd2`）
和 uTLS `v1.8.7`。`chrome`、空名、`chrome_psk`、`chrome_psk_shuffle`、
`chrome_padding_psk_shuffle`、`chrome_pq`、`chrome_pq_psk` 都选择同一个 Chrome133 模板，
与固定版别名表一致。`enabled=false` 或缺省不启用浏览器模板；没有全局默认 Chrome。
其他浏览器名称仍明确拒绝，QUIC 和 Naive 也不接受这个 stream TLS 模板。

原生 TLS 使用 `options.fingerprint="chrome133"`；原生 REALITY 使用同级
`fingerprint="chrome133"`。转换、语义检查、lowering 和 handler 都传递该值。
REALITY 仍使用自己的认证机制，不能通过普通证书配置关闭认证，也不能组合 ECH。

Android的`flow="xtls-rprx-vision"`属于外层TLS/REALITY的legacy Vision路径。
公共入口验收发现并修复了转换器同时在内层VLESS保留`vision=true`的问题，后者会触发
原生VLESS加密模式的校验并拒绝配置。本轮修正将该标记只交给外层；启用与未启用Chrome
均已通过运行时配置检查，失败证据保存在`target/android/chrome133/failed-vision-conversion/`。

## 策略与线协议

普通 TLS 的 15 个套件都对应真实 Rust 密码实现，包括 TLS1.2 ECDHE-CBC 和静态 RSA。
四个实际 group 为 X25519MLKEM768、X25519、P256、P384，初始两个 share 使用独立私钥。
REALITY 按固定 sing-box wrapper 移除 MLKEM group/share，使用独立 X25519 和客户端版本1.8.1。

ALPN 缺省为 h2/http1.1；显式列表替换该列表。ALPS 保留 h2、编号17613和空客户端设置。
CA、SPKI pin、客户端证书、校验名称和 SNI 开关继续通过原认证路径执行。关闭 SNI
不会关闭名称校验。TLS packet/record fragmentation 在同一 stream 包装上继续工作。

显式版本、cipher 或 curve 限制与完整模板冲突时返回错误，不丢弃这些限制。版本显式值
只接受1.2至1.3；curve和cipher列表需与模板一致。Vision/ECH/REALITY 的内部TLS1.3限制
仍有效：公开 ClientHello 保留兼容形状，但选择TLS1.2的服务器不能绕过内部策略。

普通 Chrome 允许一次带 RFC5746 绑定的服务器重协商，要求相同证书、ALPN和EMS连续性。
REALITY 不允许重协商。Android profile 与固定 wrapper 一样不配置恢复缓存；底层TLS库
单独提供并已验证的恢复/0-RTT API不意味着这些别名会开启0-RTT。

`rustls` 新的 `brotli-custom` feature只提供Rust编解码API，不修改默认客户端或服务端的
压缩列表。Chrome显式选择唯一Brotli解压器；默认TLS不新增压缩广告。发布依赖没有
Go/uTLS、Cronet、ring、aws-lc或C/C++密码实现。

## 验证入口

配置转换包含 Chrome 别名 × 普通/REALITY × Vision 的28种组合，另验证关闭选项、
未知profile、QUIC/Naive和错误字段。生产模块专项验证实际配置编译后的policy、CA/pin/SNI、
Vision拒绝TLS1.2，及独立Go对端的TLS1.3四种group、压缩和mTLS、TLS1.2重协商、REALITY坏认证。
测试均使用一次最多65537字节的echo；参考服务仅用于测试，不进入产品依赖。

Go对端另通过20项自检（15次成功握手、5次正确拒绝），验证修改后的key share断言：
允许并检查开头单个随机GREASE占位项，随后严格检查真实group顺序及两份独立X25519公钥。
首次生产专项中因断言遗漏GREASE而失败的日志保留在
`target/chrome-integration-stage/failed-grease-share-assertion/`。

```sh
python3 scripts/run-bounded-build.py -- cargo test --offline --locked -p aerobox-config
AEROBOX_TLS_PROFILE_PEER="$PWD/target/chrome-integration-stage/tls-profile-peer" \
AEROBOX_TLS12_RENEGOTIATION_PEER="$PWD/target/reference-peers/tls12-renegotiation" \
  python3 scripts/run-bounded-build.py -- cargo test --offline --locked \
  --manifest-path vendor/shoes/Cargo.toml --lib rustls_config_util::browser::tests \
  -- --include-ignored --test-threads=1
```

完整协议目标还包括其他浏览器profile、Naive Chromium行为、BBRv2和Android设备验收。
本实现不能单凭ClientHello相似性宣称整套浏览器网络栈等价。

## 原生构建内存

四ABI仍使用优化级别3与thin LTO。大型`shoes`包单独使用16个代码生成单元，其余包
保持1个单元，以降低LLVM在8 GiB共享主机上的工作集。首次单单元arm64构建在
4.5 GiB软阈值/5 GiB硬上限下持续换页，已中止并保留证据，不能计为已完成ABI。
发布构建策略及该变更前后的输入哈希记录在`target/android/chrome133/codegen-policy.json`。

最终原生/App流水线内存采样峰值4,835,540,992字节（约4.50 GiB），触发软阈值回收但无硬上限/OOM事件；交换峰值965,169,152字节。记录为`target/build-control/aerobox-core-build-51470.json`。

2026-11-23后续BBRv2和输入修正已验收并重新封存。当前安装包见
`target/android/app-bbr2-release/manifest.json`；本目录描述的Chrome133旧二进制已清理，
原清单、哈希、测试日志与源码快照保留，代码功能完整包含在新包。
