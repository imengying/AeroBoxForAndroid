#!/usr/bin/env python3
"""Public test vectors only: independent Python integer pow, never production keys.

Run manually to regenerate vectors.json. The Rust constants are separately
compared with rustls's RFC 7919 p/g values by the unit test. No Rust code or
cryptographic backend under test is used to calculate these expected results.
"""
import hashlib
import json
from pathlib import Path
import re

fixture_dir = Path(__file__).resolve().parent
parameters = (fixture_dir / "params.rs").read_text()
vectors = []
for bits in (2048, 3072):
    modulus_hex = re.search(
        rf"Modulus{bits},\s*U{bits},\s*\"([0-9a-f]+)\"", parameters
    ).group(1)
    prime = int(modulus_hex, 16)
    width = bits // 8
    exponent_bytes = 32 if bits == 2048 else 48

    def append_case(label, local, remote):
        x = int.from_bytes(local, "big")
        y = int.from_bytes(remote, "big")
        peer = pow(2, y, prime)
        shared = pow(peer, x, prime).to_bytes(width, "big")
        vectors.append(
            {
                "group": bits,
                "case": label,
                "secret": local.hex(),
                "public": pow(2, x, prime).to_bytes(width, "big").hex(),
                "peer": peer.to_bytes(width, "big").hex(),
                "shared": shared.hex(),
            }
        )

    append_case("dense", b"\xff" * exponent_bytes, b"\xa5" * exponent_bytes)
    append_case("alternating", b"\xaa" * exponent_bytes, b"\x55" * exponent_bytes)
    local = bytearray(exponent_bytes)
    local[0], local[-1] = 128, 1
    remote = bytearray(local)
    remote[-1] = 42
    append_case("sparse", local, remote)

    local = bytearray(hashlib.shake_256(f"aerobox-public-ffdhe{bits}".encode()).digest(exponent_bytes))
    local[0] |= 128
    for attempt in range(4096):
        remote = bytearray(hashlib.shake_256(f"public-peer-{bits}-{attempt}".encode()).digest(exponent_bytes))
        remote[0] |= 128
        peer = pow(2, int.from_bytes(remote, "big"), prime)
        shared = pow(peer, int.from_bytes(local, "big"), prime).to_bytes(width, "big")
        if shared[0] == 0:
            append_case("leading-zero", local, remote)
            break
    else:
        raise RuntimeError("bounded public fixture search found no leading-zero result")

(fixture_dir / "vectors.json").write_text(json.dumps(vectors, indent=2) + "\n")
print(f"Wrote {len(vectors)} public arithmetic test vectors")
