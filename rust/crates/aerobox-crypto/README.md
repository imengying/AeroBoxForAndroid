# AeroBox RustCrypto provider

这个独立 Rust 2024 crate 提供显式选择的 `rustls 0.23.46` 密码提供者，
支持 TLS 1.2、TLS 1.3 和 QUIC 所需的包保护及头部保护。它复用固定版本
`rustls-rustcrypto 0.0.2-alpha` 的 TLS 签名、密钥交换和记录算法，
通过 RustCrypto 的 AES-GCM、ChaCha20-Poly1305 和 AES 补齐 QUIC 接口。

```rust
let config = rustls::ClientConfig::builder_with_provider(
    aerobox_crypto::shared_provider(),
)
.with_safe_default_protocol_versions()?
.with_root_certificates(root_store)
.with_no_client_auth();
```

调用方提供正常的信任根和目标主机名。该 crate 不改变进程的默认提供者，
也不关闭证书或主机名验证；`provider()` 返回可配置的独立实例，
`shared_provider()` 复用同一个 `Arc<CryptoProvider>`。

覆盖三种 TLS 1.3 套件和六种 ECDHE TLS 1.2 套件：AES-128-GCM、
AES-256-GCM、ChaCha20-Poly1305，TLS 1.2 分别支持 ECDSA/RSA 认证。
密钥交换使用 X25519、P-256、P-384、P-521。对上游 alpha 增加了以下适配：

- 增加 P-521 ECDSA SHA-256/384/512 验证、TLS SHA-512 签名、PKCS#8/SEC1 私钥及 mTLS；独立 Go 固定向量和 TLS 1.2/1.3 组合已通过。
- 按 rustls 内置提供者的界限设置 AES-GCM 每个 TLS 密钥最多 `2^24` 条记录。
- 按 RFC 9001 设置 QUIC 保密性和完整性界限，支持密钥更新及路径专用 nonce。
- 拒绝 X25519 全零共享秘密，拒绝 NIST 曲线不符合 TLS 要求的压缩公钥编码。
- 接受 ChaCha20 头部保护的完整 32 位计数器范围，先校验输入再修改头部。
- 对过短的 TLS 1.2 ChaCha20 记录返回错误，修复上游整数下溢。
- 修复 AES 记录流量密钥导出的算法标签及 TLS 1.2 完整 IV 组装。

依赖树不含 ring、AWS-LC、OpenSSL、C 密码库或 `cc` 构建依赖。
Rust 的 `libc` 绑定仍用于操作系统随机数及 CPU 能力查询。
此结论只适用于本 crate 的依赖树；完整应用需要另外检查 feature 合并和最终链接产物。
`hpke` 模块提供 ECH 所需的 RFC 9180 Base 模式：X25519/P-256/P-384/P-521 的 KEM，分别支持 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305，共 12 个套件。九个标准测试向量各验证 257 条连续消息，另外覆盖全部套件的密钥格式、认证失败及重放拒绝。ECH 的配置、DNS 和握手策略位于内核。REALITY、ML-KEM、ML-DSA 由仓库内其他模块实现。

上游提供者仍是 alpha，并明确不建议生产使用。本地补充测试不等于安全审计，
也不代表完成 Android 真机性能、跨实现互通或全部证书算法兼容性验收。
上游密钥生成遇到操作系统随机数故障时的错误处理也尚未重写。
参考：[RustCrypto 提供者](https://github.com/RustCrypto/rustls-rustcrypto)、
[rustls 密码接口](https://docs.rs/rustls/latest/rustls/crypto/index.html)。

从仓库根目录执行：

```sh
cargo test --offline --manifest-path crates/aerobox-crypto/Cargo.toml
cargo clippy --offline --manifest-path crates/aerobox-crypto/Cargo.toml --all-targets -- -D warnings
```

测试在内存中完成，不依赖网络、OpenSSL 可执行文件或系统证书目录。
内容包括全部 TLS 套件、ECDSA/RSA 认证、错误主机名、三种 QUIC 套件的握手和
双向数据加密、密钥更新、全部密钥交换组、低阶/错误公钥、头部边界和数据篡改。
AES-GCM 与 ChaCha20 完整包的预期字节来自
[RFC 9001 附录 A](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A)。
证书、私钥及额外向量的生成说明见 `tests/fixtures/README.md` 和对应测试注释。
