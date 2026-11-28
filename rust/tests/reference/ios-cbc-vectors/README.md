# Independent TLS1.2 SHA2-CBC vectors

`generate.py` uses Python's standard-library HMAC/SHA256/SHA384 and the already installed OpenSSL CLI for AES. It verifies the complete four-block AES-128-CBC and AES-256-CBC examples from [NIST SP800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final), sections F.2.1 and F.2.5, before generating any fixture. OpenSSL is a test-data generator only: no product dependency, build script or native crypto backend is added.

The generated `crates/aerobox-crypto/tests/fixtures/ios-cbc-sha2.json` contains three record algorithms: AES128/HMAC-SHA256, AES256/HMAC-SHA256, and AES256/HMAC-SHA384. Each has 256 authenticated padding lengths, 14 block-aligned ciphertexts containing deliberately wrong MACs or padding, eight outbound records from empty through 16,384 bytes, seven sequence boundary examples through `u64::MAX`, and an authenticated but invalid 16,385-byte fragment. These total 858 records. The two PRF/transcript fixtures use independent standard-library HMAC/hash operations.

`verify.go` independently checks the fixture with Go's standard-library AES-CBC, HMAC and hashes. It validates exact ciphertext, plaintext, record validity, explicit IV derivation, PRF output and transcript hash. It has no module dependencies. The IV derivation is this Rust implementation's design; TLS1.2 permits independent explicit IV choices, so this field is not a browser wire-fingerprint requirement.

From the repository root, regenerate only if deliberately updating the checked-in fixture:

```sh
python3 tests/reference/ios-cbc-vectors/generate.py crates/aerobox-crypto/tests/fixtures/ios-cbc-sha2.json
```

The parent should run the Go check through the shared build lock after staging the files into its validation overlay:

```sh
python3 scripts/run-bounded-build.py -- go run -p=1 tests/reference/ios-cbc-vectors/verify.go crates/aerobox-crypto/tests/fixtures/ios-cbc-sha2.json
```

At source handoff, Python/OpenSSL generation and NIST examples have run successfully. Go and Rust compilation/execution have **not** run; these files do not claim otherwise.
