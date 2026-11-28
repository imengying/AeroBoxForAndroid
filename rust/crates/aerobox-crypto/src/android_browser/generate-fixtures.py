#!/usr/bin/env python3
"""Independent OpenSSL CLI ECDSA/SHA1 vectors and strong/weak chain fixtures.

OpenSSL is a fixture generator only, never linked by the Rust implementation.
Fresh test keys/certificates are random; checked-in outputs are the test oracle.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def main():
    with tempfile.TemporaryDirectory(prefix='aerobox-browser-ecdsa-') as temp:
        work = Path(temp)
        commands = []

        def run(*args):
            commands.append(list(args))
            return subprocess.check_output(['openssl', *args], cwd=work, stderr=subprocess.DEVNULL)

        run('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', 'ca-key.pem')
        run('req', '-new', '-x509', '-sha256', '-days', '7300', '-key', 'ca-key.pem',
            '-subj', '/CN=AeroBox browser signature fixture CA', '-set_serial', '90210',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', 'ca.pem')
        ca = run('x509', '-in', 'ca.pem', '-outform', 'DER')
        (work/'extensions.conf').write_text(
            'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
            'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost\n')
        output = dict(generator=run('version').decode().strip(), ca_der=ca.hex(), curves=[])
        for index, curve in enumerate(['P-256', 'P-384', 'P-521']):
            run('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:'+curve, '-out', 'key.pem')
            key = run('pkcs8', '-topk8', '-nocrypt', '-in', 'key.pem', '-outform', 'DER')
            spki = run('pkey', '-in', 'key.pem', '-pubout', '-outform', 'DER')
            run('req', '-new', '-key', 'key.pem', '-subj', '/CN=localhost', '-out', 'leaf.csr')
            certs = {}
            for hash_name in ['sha256', 'sha1']:
                der = run('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca-key.pem',
                          '-set_serial', str(100+index), '-days', '7300', '-'+hash_name,
                          '-extfile', 'extensions.conf', '-outform', 'DER')
                certs[hash_name+'_cert_der'] = der.hex()
            vectors = []
            for message in [b'', b'client random\0server random\0ECDHE parameters', bytes(range(256))+b'\xff']:
                (work/'message.bin').write_bytes(message)
                signature = run('dgst', '-sha1', '-sign', 'key.pem', 'message.bin')
                (work/'signature.der').write_bytes(signature)
                run('pkey', '-in', 'key.pem', '-pubout', '-out', 'public.pem')
                assert run('dgst', '-sha1', '-verify', 'public.pem', '-signature', 'signature.der',
                           'message.bin').strip() == b'Verified OK'
                vectors.append(dict(message=message.hex(), signature=signature.hex()))
            output['curves'].append(dict(curve=curve, key_der=key.hex(), public_spki=spki.hex(),
                                         vectors=vectors, **certs))
        output['commands_sha256'] = hashlib.sha256(json.dumps(commands).encode()).hexdigest()
        (HERE/'sha1-fixtures.json').write_text(json.dumps(output, indent=2)+'\n')


if __name__ == '__main__':
    main()
