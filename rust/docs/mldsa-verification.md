# Naive 150 的纯 Rust ML-DSA 验证基础

2026-11-26：ML-DSA-44、65、87 的 TLS1.3 CertificateVerify 和 X.509 签名验证
已合入 `aerobox-crypto::mldsa`。调用者必须显式组合算法集合；普通 provider 和已有
浏览器指纹的签名列表未变。这是 Naive 150 所需的密码基础，尚未启用完整 Naive
Chromium ClientHello，也未进入本日此前封存的 randomized/360 APK。

实现使用现有 RustCrypto `vendor/ml-dsa`，没有引入 C/C++ 密码实现。三组参数分别
检查公钥/签名长度及签名规范编码，使用空 FIPS204 context，不做 HashML-DSA。
WebPKI 匹配参数缺省的 AlgorithmIdentifier；NULL 参数和错误 OID 被拒绝。
TLS1.2 实际选择这三种签名算法也会被拒绝。此模块不提供 ML-DSA 私钥加载或客户端签名。

开发与发布模式各通过10项基础测试：239个独立公开向量包含178个空context有效样本、
61个拒绝样本；后者包括6个对原非空context有效、但不能用作TLS签名的样本。
还覆盖三个参数集互换、错误消息/公钥/签名、OID/NULL/BIT STRING约束及1MiB线程栈。
armv7源码检查与四ABI纯Rust活动依赖审计通过。

独立Go生成9组证书链，并分别由Go和OpenSSL验证：每个参数集都包含经典CA签发PQ叶子、
PQ CA签发经典叶子及完整PQ链。Rust开发/发布模式各4项外部测试通过，检查域名、有效期、
EKU、损坏签名、缺失中间证书、默认provider隔离，以及重新签名后仍须拒绝的NULL参数。
每种模式还完成11条真实OpenSSL TLS1.3连接，覆盖三个参数集、三种链结构和三套TLS1.3
密码套件；每条双向各传输65,537字节，并检查TLS正常关闭。Go/OpenSSL仅用作测试对端。

可复现入口见 [独立证书测试](../tests/reference/mldsa-chain-reference/README.md)。验收记录：
`target/naive150-foundations-stage/mldsa-status.json`、
`target/mldsa-chain-reference-stage/status.json`、
`target/mldsa-chain-tests-stage/status.json`；合并清单为
`target/mldsa-merge-stage/applied.json`。原始失败记录保留：新增路径依赖暴露了隔离目录中
Cargo工作区推断的问题，已在rustls package中明确指定其父工作区，随后全部验证重跑通过。
