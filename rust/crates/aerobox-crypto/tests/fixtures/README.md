These certificates and private keys are public test fixtures for localhost.
They must never be used by a deployed server. Certificates contain only the
localhost DNS name and have a validity window starting in November 2026.
Tests use a fixed verification time in 2030.

OpenSSL generated the checked-in fixture files; OpenSSL is not a runtime,
build or test dependency. Tests load DER directly through the RustCrypto
provider, exercising ECDSA P-256 and RSA-2048 certificate authentication.

The `p521-*` fixtures were generated separately by Go's standard library using
`CGO_ENABLED=0 go run generate-p521.go` in this directory. They include a P-521
root, leaf certificates signed with SHA-256/384/512, PKCS#8 and SEC1 keys,
independent message signatures, and a Go ECDH shared-secret vector. The same
leaf is permitted for server and client authentication. Tests use these to
check TLS 1.2/1.3 mutual authentication, P-521 key exchange, malformed inputs
and mismatched keys. Go is needed only when regenerating the checked-in data.
