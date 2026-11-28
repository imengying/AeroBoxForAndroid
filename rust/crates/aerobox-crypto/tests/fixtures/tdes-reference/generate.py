#!/usr/bin/env python3
"""Test-only independent OpenSSL block cipher + Python TLS record HMAC vectors."""
from pathlib import Path
import hashlib
import hmac
import json
import subprocess

root=Path(__file__).resolve().parent
key=bytes.fromhex('0123456789abcdef23456789abcdef01456789abcdef0123')
mac=bytes(range(20));initial_iv=bytes.fromhex('0011223344556677')
label=b'aerobox/tls-tdes-explicit-iv-key/v1\0'
iv_key=hmac.digest(mac,label+key,'sha256')[:24]
def cipher(data,key,iv=None):
    args=['openssl','enc','-des-ede3-cbc' if iv is not None else '-des-ede3','-nopad','-nosalt','-K',key.hex()]
    if iv is not None:args+=['-iv',iv.hex()]
    return subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
def record(version,seq,plain,iv,pad=None,corrupt=None):
    aad=seq.to_bytes(8,'big')+bytes([23])+version.to_bytes(2,'big')+len(plain).to_bytes(2,'big')
    tag=hmac.digest(mac,aad+plain,'sha1')
    pad=pad if pad is not None else 8-(len(plain)+20)%8
    body=bytearray(plain+tag+bytes([pad-1])*pad)
    if corrupt=='mac':body[len(plain)]^=1
    if corrupt=='padding':body[-1]^=1
    encrypted=cipher(body,key,iv)
    return (b'' if version==0x301 else iv)+encrypted,encrypted[-8:]
output=dict(source='OpenSSL DES-EDE3 block encryption; Python hashlib/hmac TLS authentication',
    openssl=subprocess.check_output(['openssl','version'],text=True).strip(),key=key.hex(),mac=mac.hex(),iv=initial_iv.hex(),
    primitive=dict(plaintext='0123456789abcdef',ciphertext=cipher(bytes.fromhex('0123456789abcdef'),key).hex()),
    records=[],padding=[],invalid=[])
for version in [0x301,0x302,0x303]:
    previous=initial_iv
    for seq,length in enumerate([0,1,7,8,9,31,255,1024,16384]):
        plain=bytes((i*17+seq)%251 for i in range(length))
        iv=previous if version==0x301 else cipher(seq.to_bytes(8,'big'),iv_key)
        encoded,previous=record(version,seq,plain,iv)
        output['records'].append(dict(version=version,sequence=seq,plain=plain.hex(),ciphertext=encoded.hex()))
    for pad in range(1,257):
        plain=bytes([42])*((8-(20+pad)%8)%8)
        iv=initial_iv if version==0x301 else bytes.fromhex('8899aabbccddeeff')
        encoded,_=record(version,42,plain,iv,pad)
        output['padding'].append(dict(version=version,padding=pad,plain=plain.hex(),ciphertext=encoded.hex()))
    for corrupt in ['mac','padding']:
        plain=b'independent bad record';iv=initial_iv
        encoded,_=record(version,42,plain,iv,corrupt=corrupt)
        output['invalid'].append(dict(version=version,fault=corrupt,ciphertext=encoded.hex()))
(root/'vectors.json').write_text(json.dumps(output,indent=2)+'\n')
print(json.dumps(dict(records=len(output['records']),padding=len(output['padding']),invalid=len(output['invalid']),
    sha256=hashlib.sha256((root/'vectors.json').read_bytes()).hexdigest())))
