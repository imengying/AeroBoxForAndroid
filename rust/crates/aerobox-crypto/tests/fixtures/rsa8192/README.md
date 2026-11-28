This is disposable test material generated independently with Go's standard
library. The private key is public test data and must never be used outside
tests. No Go code is included in AeroBox product binaries.

`ca.der` is an RSA-2048 CA. It signs the RSA-8192 `leaf.der` for
`rsa8192.aerobox.test`; the leaf permits both `digitalSignature` and
`keyEncipherment` and server/client authentication. Both certificates are valid
from 2020-01-01 through 2100-01-01. `key.der` uses PKCS#8; `public.der` uses
PKCS#1. The PEM files contain the same certificates/key.

The six signatures cover the exact bytes in `message.bin`:

```text
AeroBox independent Go RSA-8192 fixture
```

There is no final newline in the message. The PKCS#1 v1.5 and RSA-PSS signatures
each use SHA-256, SHA-384 or SHA-512 as named by their files. PSS uses a salt the
same length as its digest. Generation also verifies all six signatures in Go.

Regenerate from the repository root (fresh keys and signatures will differ):

```sh
CGO_ENABLED=0 GOMAXPROCS=2 go run crates/aerobox-crypto/tests/fixtures/rsa8192/generate.go crates/aerobox-crypto/tests/fixtures/rsa8192
```
