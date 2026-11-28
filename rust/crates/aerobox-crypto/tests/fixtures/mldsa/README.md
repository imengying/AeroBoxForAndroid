# ML-DSA verification vectors

The three JSON files are byte-for-byte copies of the public C2SP/Wycheproof
`testvectors_v1/mldsa_{44,65,87}_verify_test.json` at commit
`0fd0ec1cf2114f456f5c3e7c61ba807fb1311b45`:

<https://github.com/C2SP/wycheproof/tree/0fd0ec1cf2114f456f5c3e7c61ba807fb1311b45/testvectors_v1>

This commit is the `thirdparty/wycheproof` gitlink of RustCrypto/signatures
`a39b5af54724e33e70b336b4b483bca8c0f49730`, the revision recorded in the vendored
`ml-dsa` crate's `.cargo_vcs_info.json`. The copied upstream license is
`LICENSE-WYCHEPROOF`.

| Parameter set | SHA-256 | Cases | Valid empty context | Valid nonempty context | Invalid empty context | Invalid nonempty context |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 44 | e6530fc2a76adcae3c62e2403fc1096d3170ff3c6c13b7ad1dc0b282afd4d6c8 | 80 | 61 | 2 | 16 | 1 |
| 65 | 2ebc037bfa7b64e1343dee49f2398bb01c683e4fafd5aab30153786f952359b7 | 83 | 63 | 2 | 17 | 1 |
| 87 | 6148cbaac729df9115a7061ea47e6a5b61104236eb8e961a11af31a0d05e4274 | 76 | 54 | 2 | 19 | 1 |

The integration test asserts all five counts for each parameter set, distinct
`tcId`s and `numberOfTests`. Every source case invokes the adapter; malformed
test JSON or hex causes a test failure. It does not skip invalid-length keys.
The original corpus's `valid` result is interpreted in its original context.
Our TLS/PKIX adapter fixes the context to empty, so its expected result is
success only for the 178 valid empty-context cases; all other 61 cases must
fail, including the six source-valid nonempty-context cases.

This is the complete verification corpus for these three files at the pinned
commit, not the full Wycheproof suite or NIST validation. It does not establish
certificate-chain policy or live TLS handshake correctness. The original
vendored `tests/wycheproof.rs` verifier macro hardcodes `MlDsa44` and skips keys
that do not fit that type; the new test dispatches all three types explicitly.
The signing/key-generation corpora and nonempty-context API are outside scope.
