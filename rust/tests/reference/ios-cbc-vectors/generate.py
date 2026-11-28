#!/usr/bin/env python3
"""Offline test data only: Python HMAC/PRF plus the installed OpenSSL AES CLI.

This is not a product dependency. No compiler, Rust code, Rust encryption, or
hand-written AES implementation participates in generation. Go's independent
standard-library verifier can subsequently check every record and PRF byte.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import subprocess

LABEL = b'aerobox/tls12-cbc-sha2-explicit-iv-key/v1\0'


def aes(key, data, iv=None):
    assert len(data) % 16 == 0
    mode = 'ecb' if iv is None else 'cbc'
    command = ['openssl', 'enc', f'-aes-{len(key) * 8}-{mode}', '-K', key.hex(), '-nopad', '-nosalt']
    if iv is not None:
        command += ['-iv', iv.hex()]
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    assert len(result.stdout) == len(data), result.stderr
    return result.stdout


def kat():
    # NIST SP800-38A F.2.1/F.2.5, complete four-block CBC known answers.
    plain = bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'
                          '30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710')
    iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    for key, expected in [
        ('2b7e151628aed2a6abf7158809cf4f3c',
         '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2'
         '73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7'),
        ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
         'f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d'
         '39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b'),
    ]:
        assert aes(bytes.fromhex(key), plain, iv).hex() == expected


def prf(digest, secret, label, seed, length):
    a, out = label + seed, bytearray()
    while len(out) < length:
        a = hmac.digest(secret, a, digest)
        out.extend(hmac.digest(secret, a + label + seed, digest))
    return bytes(out[:length])


def record(name, key, mac, digest, plain, seq, pad=None, fault=None, derived=False):
    tag = hmac.digest(mac, seq.to_bytes(8, 'big') + b'\x17\x03\x03' + len(plain).to_bytes(2, 'big') + plain, digest)
    if pad is None:
        pad = 16 - (len(plain) + len(tag)) % 16
    assert 1 <= pad <= 256 and (len(plain) + len(tag) + pad) % 16 == 0
    iv = b'\x33' * 16
    if derived:
        iv_key = hmac.digest(mac, LABEL + len(key).to_bytes(2, 'big') + len(mac).to_bytes(2, 'big') + key, 'sha256')
        iv = aes(iv_key, bytes(8) + seq.to_bytes(8, 'big'))
    clear = bytearray(plain + tag + bytes([pad - 1]) * pad)
    if fault == 'bad-mac':
        clear[len(plain)] ^= 0x80
    elif fault == 'bad-padding':
        clear[-1] ^= 1
    elif fault not in (None, 'oversized-plaintext'):
        raise ValueError(fault)
    wire = iv + aes(key, clear, iv)
    return dict(name=name, sequence=seq, plaintext_hex=plain.hex(), padding=pad,
                valid=fault is None, fault=fault, derived_iv=derived, tag_hex=tag.hex(), wire_hex=wire.hex())


def generate():
    kat()
    groups = []
    for key_len, digest in [(16, 'sha256'), (32, 'sha256'), (32, 'sha384')]:
        mac_len = hashlib.new(digest).digest_size
        key, mac = b'\x11' * key_len, b'\x22' * mac_len
        vectors = []
        for pad in range(1, 257):
            plain = b'\x5a' * ((-mac_len - pad) % 16)
            vectors.append(record(f'padding-{pad}', key, mac, digest, plain, 0x100000001, pad))
            if pad in (1, 2, 15, 16, 17, 255, 256):
                for fault in ('bad-padding', 'bad-mac'):
                    vectors.append(record(f'{fault}-{pad}', key, mac, digest, plain, 0x100000001, pad, fault))
        for i, length in enumerate((0, 1, 15, 16, 17, 255, 1024, 16384)):
            plain = bytes((i * 29 + 7) % 251 for i in range(length))
            vectors.append(record(f'derived-{length}', key, mac, digest, plain, (1 << 32) + i, derived=True))
        for seq in (0, 1, 255, 256, (1 << 32) - 1, 1 << 32, (1 << 64) - 1):
            vectors.append(record(f'sequence-{seq}', key, mac, digest, b'sequence boundary', seq, derived=True))
        vectors.append(record('oversized-plaintext', key, mac, digest, b'\x55' * 16385, 17, fault='oversized-plaintext'))
        groups.append(dict(key_hex=key.hex(), mac_key_hex=mac.hex(), digest=digest, vectors=vectors))
    secret, seed, transcript = bytes(range(48)), bytes(range(64)), b'ClientHello\0ServerHello\0CertificateVerify\0'
    prfs = []
    for digest in ('sha256', 'sha384'):
        prfs.append(dict(digest=digest, secret_hex=secret.hex(), label_hex=b'master secret'.hex(),
                         seed_hex=seed.hex(), output_hex=prf(digest, secret, b'master secret', seed, 100).hex(),
                         transcript_hex=transcript.hex(), transcript_hash_hex=hashlib.new(digest, transcript).hexdigest()))
    return dict(format=1, source='Python stdlib HMAC/PRF plus installed OpenSSL CLI AES; NIST F.2.1/F.2.5 checked',
                openssl=subprocess.check_output(['openssl', 'version'], text=True).strip(), groups=groups, prfs=prfs)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    data = generate()
    args.output.write_text(json.dumps(data, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'records': sum(len(g['vectors']) for g in data['groups']),
                      'prfs': len(data['prfs']), 'nist_aes_cbc': 'passed', 'openssl': data['openssl']}))
