# Edge85 / QQ11.1 TLS 实现

2026-11-23，Android固定版本的`fingerprint=edge`对应uTLS `HelloEdge_85`，
`fingerprint=qq`对应`HelloQQ_11_1`。实现已于北京时间2026-11-24合入主源码，并进入2026-11-25的四ABI安装包。
原生配置分别为`edge85`、`qq11_1`，不能视为当前Edge或QQ浏览器版本的通用承诺。

## 实现及边界

两个模板均提供真实TLS1.0–1.3能力：15个密码套件、8个握手签名算法、X25519/P256/P384，
首次只产生一个真实X25519 key share，并保留模板的GREASE份额。旧版本明确使用
RustCrypto PRF、CBC、签名和Finished实现；普通默认TLS配置不开放旧版本。
QQ发送17513 ALPS的h2选项，Edge不发送ALPS；两者支持Brotli证书解压与ALPN覆盖。

首次扩展顺序固定。条件padding按固定uTLS的BoringSSL规则实现，长度输入包含4字节握手头、
不包含5字节record头；unpadded508..511时，上游要求至少1个payload padding字节，
最终握手长度会是513..516，并非一律512。Cookie HRR按上游对象列表随机插入扩展，
未发出的SNI对象仍参与槽位计算。换组HRR只保留新组share；仅Cookie的HRR保留原share。

TLS1.0/1.1/1.2支持一次服务端发起的安全重协商，检查双方Finished绑定、版本、证书、
ALPN和EMS连续性，重新验证客户端证书，重新生成会话密钥。
旧epoch应用数据在CCS前可接收；新epoch的Finished通过前不交付应用数据。
不允许再次重协商或初次缺少安全绑定时发送`no_renegotiation`警告；
篡改绑定、签名、证书或Finished则进入永久失败状态。

生产接入保留指定的profile枚举，REALITY不会把Edge/QQ换成Chrome。
Vision和REALITY只接受TLS1.3，封面ClientHello保留对应模板字段；普通流TLS可协商旧版本。
QUIC、Naive、ECH以及互相矛盾的显式版本/套件/曲线配置明确拒绝。
REALITY没有可执行的显式`curve_preferences`选项，转换器拒绝该字段，避免原先静默丢弃。

客户端新增ALPN单项、列表和ClientHello总扩展长度检查，普通TLS与浏览器profile均覆盖。
检查发生在不定长字段构造及序列化前，避免debug断言失败或release截断u16长度。
Android离线检查也检查ALPN单项和明显超限的总长度；其不构造真实握手，不宣称验证完整网络交互。

## 已完成证据

- `target/browser-profile-final-stage/evidence/`：密码库开发版及发布版各123项全部通过，
  包含已有Android11、Chrome133、ECH、静态RSA、QUIC密码和TLS重协商回归。
- `target/browser-profile-core-stage/evidence/wire-comparison.json`：28组Edge/QQ完整首次记录
  逐字节比较，涵盖SNI关闭/IP/最长DNS名称、自定义ALPN及可达padding边界。
  只消除随机数、session ID、临时公钥和GREASE样本值，并单独验证GREASE槽位关系。
- `target/browser-hrr-rust-stage/evidence/comparison.json`：116组独立HRR输入、232个握手报文，
  核对所有非随机字节、实际record/CCS、Cookie合法位置、两种key-share规则及第二飞padding。
  该捕获只验证构造；完整认证的Cookie HRR另外由TLS profile Go对端验证。
- 独立旧版重协商Go夹具已通过243个网络场景及参数检查；其已知宽松ALPN/EMS策略与
  旧epoch接收限制在测试中单独记录，Rust测试不以这些限制降低校验要求。

2026-11-24（北京时间）已将57个文件的增量合入主源码；封存输入共3776个文件，
SHA256为`36e77bbb83eed4647f3b8f84ff57e4b6cf65ba80a895cb9e2c10ffb0a3972680`。
最终验证：42项配置、2867项内核、409项Quinn、18项独立Go协议互通、
9项浏览器专项和29项Android主机测试全部通过。四ABI活动依赖审计和armv7密码源码检查通过。
源码、补丁、验证与复用证据保存在`target/android/edge-qq/`；后续打包见下，尚未做真机验收。

ECDSA三种TLS1.2套件×两个模板×无客户端证书/RSA/ECDSA客户端证书，
开发版和发布版各18次独立Go连接均通过；验证完整证书链、65537字节双向数据、
EMS exporter、OCSP及关闭，证据位于`target/browser-ecdsa-stage/`。

生产内核首轮2867项、Quinn409项已通过。Android公共入口随后发现显式静态RSA套件的
IANA名称被错误拒绝：选择器使用rustls的Debug显示名称，其中部分枚举会显示为十六进制。
隔离修正改用`CipherSuite::as_str()`，回归测试改为真实外部名称；重建后完整内核、
浏览器、独立协议和Android入口均已重复验证。配置转换和Quinn本次没有依赖该修改，
复用其已通过结果并保存来源。测试目录的Cargo workspace发现问题已通过
在仓库外复制同哈希源码解决，未为测试改动产品manifest。

生产内核与Android入口最终验证记录在
`target/browser-native-stage/status.json`。成功构造ClientHello不等于认证成功，
本文没有把参考捕获EOF算作成功连接。2026-11-25的最新封存清单为
`target/android/app-browser-profiles-release/manifest.json`，已包含Edge/QQ、Android11及
Safari/iOS指纹增量；四ABI共八个APK、138项JVM与JNI/DEX检查通过。

## 来源与资源控制

固定参考为MetaCubeX/uTLS v1.8.7及Android绑定的sing-box v1.14.4。
新增Go工具仅测试使用，产品及密码依赖保持纯Rust；实现使用Rust2024工程约定。
vendored rustls保留其原有edition以减少无关变更。
所有编译通过同一构建锁，jobs=1，MemoryHigh4.5GiB、MemoryMax5GiB、SwapMax1GiB；
主代理和一个子代理并行处理源码和审查。

后续 Firefox 合并快照已完成四 ABI 打包；当前最新清单为
`target/android/app-firefox-release/manifest.json`，验证范围见 [Firefox 接入](firefox-integration.md)。
