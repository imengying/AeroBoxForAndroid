"""Synthetic parser/validator tests. These are not uTLS captures or handshakes."""
import unittest

from analyze import HRR_RANDOM, DecodeError, analyze, expected_padding


def uint(value, size=2):
    return value.to_bytes(size, 'big')


def vector(data, size=2):
    return uint(len(data), size) + data


def ext(typ, data):
    return uint(typ) + vector(data)


def message(typ, data):
    return bytes([typ]) + vector(data, 3)


def record(data, typ=22, version=0x303):
    return bytes([typ]) + uint(version) + vector(data)


COOKIE = b'aerobox-cookie'
SLOTS = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a]
CIPHERS = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
           0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]


def object_name(typ):
    return {21: '*tls.UtlsPaddingExtension', 44: '*tls.CookieExtension',
            SLOTS[2]: '*tls.UtlsGREASEExtension', SLOTS[3]: '*tls.UtlsGREASEExtension'}\
        .get(typ, f'*tls.Extension{typ}')


def build_hello(*, changed=False, cookie_slot=None, name_len=22, no_sni=False):
    share = uint(23) + vector(b'\x04' + bytes([7]) * 64) if changed else (
        uint(SLOTS[1]) + vector(b'\x00') + uint(29) + vector(bytes([6]) * 32))
    entries = [
        (SLOTS[2], b''),
        (0, None if no_sni else vector(b'\x00' + vector(b'a' * name_len))),
        (23, b''), (65281, b'\x00'),
        (10, vector(b''.join(uint(v) for v in [SLOTS[1], 29, 23, 24]))),
        (11, b'\x01\x00'), (35, b''), (16, vector(vector(b'h2', 1) + vector(b'http/1.1', 1))),
        (5, b'\x01\x00\x00\x00\x00'), (13, vector(uint(0x0403) + uint(0x0804))),
        (18, b''), (51, vector(share)), (45, b'\x01\x01'),
        (43, vector(b''.join(uint(v) for v in [SLOTS[4], 0x304, 0x303, 0x302, 0x301]), 1)),
        (27, b'\x02\x00\x02'), (SLOTS[3], b'\x00'), (21, None),
    ]
    if cookie_slot is not None:
        entries.insert(cookie_slot, (44, vector(COOKIE)))
    prefix = uint(0x303) + bytes([1]) * 32 + vector(bytes([2]) * 32, 1)
    prefix += vector(b''.join(uint(v) for v in [SLOTS[0]] + CIPHERS)) + vector(b'\x00', 1)
    unpadded = len(message(1, prefix + vector(b''.join(ext(t, p) for t, p in entries if p is not None))))
    pad = expected_padding(unpadded)
    entries = [(t, bytes(pad - 4) if t == 21 and pad else p) for t, p in entries]
    encoded = message(1, prefix + vector(b''.join(ext(t, p) for t, p in entries if p is not None)))
    objects = [{'type': object_name(t), 'wire_length': 0 if p is None else 4 + len(p)} for t, p in entries]
    return encoded, objects, unpadded


def value(mode='cookie-only', slot=0, *, name_len=22, no_sni=False):
    first, before, _ = build_hello(name_len=name_len, no_sni=no_sni)
    second, after, unpadded = build_hello(changed=mode == 'cookie-group', cookie_slot=slot,
                                           name_len=name_len, no_sni=no_sni)
    body = uint(0x303) + HRR_RANDOM + vector(bytes([2]) * 32, 1) + uint(0x1301) + b'\x00'
    exts = ext(43, uint(0x304))
    if mode == 'cookie-group':
        exts += ext(51, uint(23))
    hrr = message(2, body + vector(exts + ext(44, vector(COOKIE))))
    flights = [record(first, version=0x301), record(second)]
    return dict(source='synthetic-validator-unit-test-only', name='edge', profile='Edge-85',
                mode=mode, case='synthetic', sample=0, cookie_hex=COOKIE.hex(),
                hrr_handshake_hex=hrr.hex(), hrr_record_hex=record(hrr).hex(),
                client_hellos_hex=[first.hex(), second.hex()],
                client_hello_records_hex=[p.hex() for p in flights],
                outbound_wire_hex=(flights[0] + record(b'\x01', typ=20) + flights[1]).hex(),
                built_first_hello_hex=first.hex(), objects_before=before, objects_after=after,
                has_padding_object=True, second_unpadded_hello_length=unpadded,
                handshake_complete=False, expected_eof=True, build_error='', handshake_error='EOF')


class HRRValidatorTests(unittest.TestCase):
    def test_every_allowed_object_slot_and_omitted_sni(self):
        for mode in ('cookie-only', 'cookie-group'):
            for no_sni in (False, True):
                for slot in range(15):
                    with self.subTest(mode=mode, no_sni=no_sni, slot=slot):
                        result = analyze(value(mode, slot, no_sni=no_sni))
                        self.assertTrue(result['valid'])
                        self.assertEqual(result['cookie_object_slot'], slot)
                        if no_sni:
                            self.assertIn(1, result['absent_original_objects'])

    def test_fixed_tail_cookie_is_rejected(self):
        # The reviewed Rust code's slot is legal TLS but outside uTLS's range.
        with self.assertRaisesRegex(DecodeError, 'outside pinned uTLS'):
            analyze(value(slot=15))

    def test_second_flight_padding_boundaries(self):
        for mode in ('cookie-only', 'cookie-group'):
            baseline = value(mode)
            size = baseline['second_unpadded_hello_length']
            for target in (255, 256, 507, 508, 511, 512):
                name_len = 22 + target - size
                if not 1 <= name_len <= 253:
                    continue
                with self.subTest(mode=mode, target=target):
                    sample = value(mode, name_len=name_len)
                    sample['second_unpadded_target'] = target
                    result = analyze(sample)
                    self.assertEqual(result['flights'][1]['unpadded_hello_length'], target)

    def test_permanent_evidence_mismatches_fail(self):
        mutations = (
            ('handshake_complete', True), ('expected_eof', False), ('cookie_hex', '00'),
            ('second_unpadded_hello_length', 0), ('built_first_hello_hex', '00'),
            ('hrr_record_hex', '160303000100'),
        )
        for field, replacement in mutations:
            with self.subTest(field=field):
                sample = value()
                sample[field] = replacement
                with self.assertRaises((DecodeError, KeyError)):
                    analyze(sample)

    def test_group_changing_hrr_must_remove_original_shares(self):
        sample = value()
        sample['mode'] = 'cookie-group'
        hrr = bytes.fromhex(sample['hrr_handshake_hex'])
        # Keep the original cookie-only wire: the independent HRR parser rejects it.
        self.assertNotIn(ext(51, uint(23)), hrr)
        with self.assertRaisesRegex(DecodeError, 'P256 HRR'):
            analyze(sample)

    def test_grease_collision_is_not_erased_by_normalization(self):
        sample = value()
        old = ext(SLOTS[3], b'\x00')
        new = ext(SLOTS[2], b'\x00')
        for key in ('built_first_hello_hex', 'outbound_wire_hex'):
            sample[key] = bytes.fromhex(sample[key]).replace(old, new).hex()
        for key in ('client_hellos_hex', 'client_hello_records_hex'):
            sample[key] = [bytes.fromhex(s).replace(old, new).hex() for s in sample[key]]
        with self.assertRaisesRegex(DecodeError, 'duplicate extension'):
            analyze(sample)


if __name__ == '__main__':
    unittest.main()
