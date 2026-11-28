#!/usr/bin/env python3
"""Independent OpenSSL RFC9345 fixtures. OpenSSL is never a product dependency.

Generation uses a disposable CA and fresh delegated keys. Frozen JSON is the
oracle; tests do not invoke OpenSSL or depend on certificate generation time.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
NOW = 1893456000  # 2030-01-01
NOT_BEFORE = 1577836800  # 2020-01-01


def der(tag, body):
    length = len(body)
    if length < 128:
        prefix = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        prefix = bytes([128 + len(encoded)]) + encoded
    return bytes([tag]) + prefix + body


def pieces(sequence):
    out, pos = [], 0
    while pos < len(sequence):
        start = pos
        tag, length = sequence[pos:pos + 2]
        pos += 2
        if length & 128:
            n = length & 127
            length = int.from_bytes(sequence[pos:pos + n], 'big')
            pos += n
        end = pos + length
        assert end <= len(sequence)
        out.append((tag, sequence[pos:end], sequence[start:end]))
        pos = end
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixtures', type=Path, default=HERE.parents[1] / 'tests/fixtures')
    fixture_dir = parser.parse_args().fixtures.resolve()
    with tempfile.TemporaryDirectory(prefix='aerobox-dc-fixtures-') as tmp:
        work = Path(tmp)
        commands = []

        def run(*args):
            commands.append(list(args))
            return subprocess.check_output(['openssl', *args], cwd=work, stderr=subprocess.DEVNULL)

        (work / 'issuer-key.der').write_bytes((fixture_dir / 'rsa-key.der').read_bytes())
        run('pkey', '-inform', 'DER', '-in', 'issuer-key.der', '-out', 'issuer-key.pem')
        run('req', '-new', '-x509', '-sha256', '-days', '7300', '-key', 'issuer-key.pem',
            '-subj', '/CN=AeroBox delegated credential fixture root', '-set_serial', '9345',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', 'ca.pem')
        (work / 'index').write_text('')
        (work / 'serial').write_text('0100\n')
        run('req', '-new', '-key', 'issuer-key.pem', '-subj', '/CN=localhost', '-out', 'leaf.csr')
        ca_config = ('[ca]\ndefault_ca=CA\n[CA]\ndatabase=index\nserial=serial\n'
                     'new_certs_dir=.\ncertificate=ca.pem\nprivate_key=issuer-key.pem\n'
                     'default_md=sha256\npolicy=policy\nunique_subject=no\n'
                     '[policy]\ncommonName=supplied\n[leaf]\nbasicConstraints=critical,CA:FALSE\n'
                     'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost\n')
        variants = {
            'valid': 'keyUsage=critical,digitalSignature\n1.3.6.1.4.1.44363.44=DER:05:00\n',
            'missing_usage': 'keyUsage=critical,digitalSignature\n',
            'critical_usage': 'keyUsage=critical,digitalSignature\n1.3.6.1.4.1.44363.44=critical,DER:05:00\n',
            'malformed_usage': 'keyUsage=critical,digitalSignature\n1.3.6.1.4.1.44363.44=DER:05:01:00\n',
            'missing_key_usage': '1.3.6.1.4.1.44363.44=DER:05:00\n',
            'wrong_key_usage': 'keyUsage=critical,keyEncipherment\n1.3.6.1.4.1.44363.44=DER:05:00\n',
        }
        certs = {}
        for name, extensions in variants.items():
            (work / 'ca.conf').write_text(ca_config + extensions)
            run('ca', '-batch', '-notext', '-config', 'ca.conf', '-extensions', 'leaf',
                '-startdate', '20200101000000Z', '-enddate', '20400101000000Z',
                '-in', 'leaf.csr', '-out', 'leaf.pem')
            certs[name] = run('x509', '-in', 'leaf.pem', '-outform', 'DER')
        for name, end in [('short', '20300102000000Z'), ('alternate', '20400101000000Z')]:
            (work / 'ca.conf').write_text(ca_config + variants['valid'])
            run('ca', '-batch', '-notext', '-config', 'ca.conf', '-extensions', 'leaf',
                '-startdate', '20200101000000Z', '-enddate', end,
                '-in', 'leaf.csr', '-out', 'leaf.pem')
            certs[name] = run('x509', '-in', 'leaf.pem', '-outform', 'DER')

        # Correctly re-sign a certificate with duplicate unknown noncritical
        # DelegationUsage, which a chain parser can otherwise ignore.
        outer = pieces(pieces(certs['valid'])[0][1])
        fields = pieces(outer[0][1])
        extensions = pieces(pieces(fields[-1][1])[0][1])
        usage = next(item[2] for item in extensions if bytes.fromhex('2b0601040182da4b2c') in item[2])
        tagged = der(0xa3, der(0x30, b''.join(item[2] for item in extensions) + usage))
        tbs = der(0x30, b''.join(item[2] for item in fields[:-1]) + tagged)
        (work / 'tbs.der').write_bytes(tbs)
        signature = run('dgst', '-sha256', '-sign', 'issuer-key.pem', 'tbs.der')
        certs['duplicate_usage'] = der(0x30, tbs + outer[1][2] + der(3, b'\0' + signature))

        context = b' ' * 64 + b'TLS, server delegated credentials\0'
        message = b' ' * 64 + b'TLS 1.3, server CertificateVerify\0' + hashlib.sha256(b'independent DC fixture transcript').digest()
        (work / 'message.bin').write_bytes(message)
        curves = []
        for name, scheme, digest_name in [('P-256', 0x0403, 'sha256'), ('P-384', 0x0503, 'sha384'), ('P-521', 0x0603, 'sha512')]:
            run('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:' + name, '-out', 'dc-key.pem')
            spki = run('pkey', '-in', 'dc-key.pem', '-pubout', '-outform', 'DER')
            key = run('pkcs8', '-topk8', '-nocrypt', '-in', 'dc-key.pem', '-outform', 'DER')
            cred = (NOW + 86400 - NOT_BEFORE).to_bytes(4, 'big') + scheme.to_bytes(2, 'big') + len(spki).to_bytes(3, 'big') + spki
            (work / 'delegation.bin').write_bytes(context + certs['valid'] + cred + bytes.fromhex('0804'))
            signature = run('dgst', '-sha256', '-sign', 'issuer-key.pem', '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:32', 'delegation.bin')
            dc = cred + bytes.fromhex('0804') + len(signature).to_bytes(2, 'big') + signature
            cv = run('dgst', '-' + digest_name, '-sign', 'dc-key.pem', 'message.bin')
            curves.append(dict(name=name, scheme=scheme, spki=spki.hex(), key=key.hex(), credential=dc.hex(), certificate_verify=(scheme.to_bytes(2, 'big') + len(cv).to_bytes(2, 'big') + cv).hex()))
        # Correct issuer signatures across the independent algorithm policy.
        # These are useful negative oracles: rejection must not depend on a bad
        # signature, bad certificate chain, or wrong delegated CV signature.
        issuer_cases = []
        delegated_cred = bytes.fromhex(curves[0]['credential'])
        delegated_cred = delegated_cred[:9 + len(bytes.fromhex(curves[0]['spki']))]

        def issuer_case(name, certificate, keyfile, scheme, digest_name, accepted):
            (work / 'delegation.bin').write_bytes(context + certificate + delegated_cred + scheme.to_bytes(2, 'big'))
            signature = run('dgst', '-' + digest_name, '-sign', keyfile, 'delegation.bin')
            (work / 'signature.bin').write_bytes(signature)
            run('pkey', '-in', keyfile, '-pubout', '-out', 'verify-key.pem')
            assert run('dgst', '-' + digest_name, '-verify', 'verify-key.pem', '-signature', 'signature.bin', 'delegation.bin').strip() == b'Verified OK'
            dc = delegated_cred + scheme.to_bytes(2, 'big') + len(signature).to_bytes(2, 'big') + signature
            issuer_cases.append(dict(name=name, certificate=certificate.hex(), credential=dc.hex(), accepted=accepted))

        for scheme, digest_name in [(0x0401, 'sha256'), (0x0501, 'sha384'), (0x0601, 'sha512'), (0x0201, 'sha1')]:
            issuer_case('RSA-' + digest_name, certs['valid'], 'issuer-key.pem', scheme, digest_name, False)
        for name, scheme, digest_name in [('P-256', 0x0403, 'sha256'), ('P-384', 0x0503, 'sha384'), ('P-521', 0x0603, 'sha512')]:
            run('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:' + name, '-out', 'ec-issuer-key.pem')
            run('req', '-new', '-key', 'ec-issuer-key.pem', '-subj', '/CN=localhost', '-out', 'ec-issuer.csr')
            (work / 'ca.conf').write_text(ca_config + variants['valid'])
            run('ca', '-batch', '-notext', '-config', 'ca.conf', '-extensions', 'leaf',
                '-startdate', '20200101000000Z', '-enddate', '20400101000000Z',
                '-in', 'ec-issuer.csr', '-out', 'ec-issuer.pem')
            certificate = run('x509', '-in', 'ec-issuer.pem', '-outform', 'DER')
            issuer_case(name + '-matching', certificate, 'ec-issuer-key.pem', scheme, digest_name, True)
            cross_scheme, cross_digest = (0x0503, 'sha384') if name == 'P-256' else (0x0403, 'sha256')
            issuer_case(name + '-cross', certificate, 'ec-issuer-key.pem', cross_scheme, cross_digest, False)

        run('genpkey', '-algorithm', 'ED25519', '-out', 'ed-key.pem')
        ed_spki = run('pkey', '-in', 'ed-key.pem', '-pubout', '-outform', 'DER')
        ed_key = run('pkcs8', '-topk8', '-nocrypt', '-in', 'ed-key.pem', '-outform', 'DER')
        cred = (NOW + 86400 - NOT_BEFORE).to_bytes(4, 'big') + bytes.fromhex('0807') + len(ed_spki).to_bytes(3, 'big') + ed_spki
        (work / 'delegation.bin').write_bytes(context + certs['valid'] + cred + bytes.fromhex('0804'))
        sig = run('dgst', '-sha256', '-sign', 'issuer-key.pem', '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:32', 'delegation.bin')
        ed_dc = cred + bytes.fromhex('0804') + len(sig).to_bytes(2, 'big') + sig
        ed_cv = run('pkeyutl', '-sign', '-rawin', '-inkey', 'ed-key.pem', '-in', 'message.bin')
        ed25519 = dict(spki=ed_spki.hex(), key=ed_key.hex(), credential=ed_dc.hex(), certificate_verify=(bytes.fromhex('0807') + len(ed_cv).to_bytes(2, 'big') + ed_cv).hex())
        run('req', '-new', '-key', 'ed-key.pem', '-subj', '/CN=localhost', '-out', 'ed-issuer.csr')
        run('ca', '-batch', '-notext', '-config', 'ca.conf', '-extensions', 'leaf',
            '-startdate', '20200101000000Z', '-enddate', '20400101000000Z',
            '-in', 'ed-issuer.csr', '-out', 'ed-issuer.pem')
        ed_cert = run('x509', '-in', 'ed-issuer.pem', '-outform', 'DER')
        (work / 'delegation.bin').write_bytes(context + ed_cert + delegated_cred + bytes.fromhex('0807'))
        ed_sig = run('pkeyutl', '-sign', '-rawin', '-inkey', 'ed-key.pem', '-in', 'delegation.bin')
        ed_issuer_dc = delegated_cred + bytes.fromhex('0807') + len(ed_sig).to_bytes(2, 'big') + ed_sig
        issuer_cases.append(dict(name='Ed25519', certificate=ed_cert.hex(), credential=ed_issuer_dc.hex(), accepted=True))

        output = dict(generator=run('version').decode().strip(), now=NOW, not_before=NOT_BEFORE,
                      ca=run('x509', '-in', 'ca.pem', '-outform', 'DER').hex(),
                      issuer_key=(work / 'issuer-key.der').read_bytes().hex(),
                      message=message.hex(), issuer_cases=issuer_cases, ed25519=ed25519, certificates={name: value.hex() for name, value in certs.items()}, curves=curves,
                      commands_sha256=hashlib.sha256(json.dumps(commands).encode()).hexdigest())
        (HERE / 'fixtures.json').write_text(json.dumps(output, indent=2) + '\n')


if __name__ == '__main__':
    main()
