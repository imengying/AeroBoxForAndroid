# Transport validation

这个独立工程验证 vendored Quinn 和 Hickory 的 RustCrypto 功能开关，
不引入上游测试中的 rcgen/ring 开发依赖。Cargo.lock 锁定验证使用的完整依赖图。

从仓库根目录运行：

```sh
cargo test --offline --manifest-path crates/aerobox-crypto/validation/transport/Cargo.toml
cargo tree --offline --manifest-path crates/aerobox-crypto/validation/transport/Cargo.toml --edges normal,build
```

测试覆盖默认 QUIC/DNS TLS 配置构建、握手 token 和 reset HMAC 篡改拒绝、
RFC 9001 Retry 标签，以及三个 TLS 1.3 套件分别完成的本地 UDP QUIC
Retry、65 KB 双向 stream、Datagram 和密钥更新。网络测试使用本机随机端口，
不连接外部服务。

此工程验证密码接入和 QUIC 传输，不代表完成公网代理服务互通、全部 DNS
传输互通或 Android 真机验收。核心提供者的成熟度限制见上级 README。
