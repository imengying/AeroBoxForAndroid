# Legacy RSA MD5/SHA-1 known-answer fixture

Uses the existing project test-only RSA key at `tests/fixtures/rsa-key.der` (PKCS#8, 2048-bit). Signature independently constructed in Python using `hashlib.md5`, `hashlib.sha1`, and modular exponentiation `pow(EM, d, n)`, without calling the production Rust signature implementation.

`EM = 00 01 FF...FF 00 MD5(message) SHA1(message)`, exactly one modulus wide. No DigestInfo is inserted. The Python public exponentiation is checked to recover this exact encoding. No new secret or production credential is present.

This fixture validates wire encoding only; production signing uses RustCrypto RSA blinding and fallible entropy acquisition.
