import json
from pathlib import Path
import unittest

import normalize


def vector(value, size=2):
    return len(value).to_bytes(size, 'big') + value


def record(extension_bytes):
    body = bytes.fromhex('0303') + bytes(range(32)) + vector(b'session', 1)
    body += vector(bytes.fromhex('0a0a1301')) + vector(b'\0', 1) + vector(extension_bytes)
    hello = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + vector(hello)


def extension(identity, payload):
    return identity.to_bytes(2, 'big') + vector(payload)


class Normalization(unittest.TestCase):
    def test_unknown_extensions_and_grease_relationships(self):
        raw = record(
            extension(10, vector(bytes.fromhex('2a2a0017')))
            + extension(51, vector(bytes.fromhex('2a2a000100') + bytes.fromhex('00170003') + b'\x04xy'))
            + extension(0x1234, bytes.fromhex('deadbeef'))
        )
        result = normalize.normalize_wire(raw)
        self.assertEqual(result['extensions'][-1]['normalized_data_hex'], 'deadbeef')
        self.assertEqual(result['extensions'][1]['normalized_data_hex'][-6:], '040000')
        self.assertTrue(result['all_share_groups_advertised'])
        relation = result['grease_equivalence_classes']
        self.assertEqual([item['class'] for item in relation], [0, 1, 1])
        self.assertEqual(len(bytes.fromhex(result['complete_normalized_record_hex'])), len(raw))
        self.assertNotIn('7879', result['extensions'][1]['normalized_data_hex'])

    def test_truncation_and_vector_lengths_fail(self):
        raw = record(extension(13, vector(bytes.fromhex('04030804'))))
        for cut in (1, 4, 5, 10, len(raw) - 1):
            with self.subTest(cut=cut), self.assertRaises(normalize.DecodeError):
                normalize.normalize_wire(raw[:cut])
        with self.assertRaises(normalize.DecodeError):
            normalize.normalize_wire(record(extension(13, vector(b'\x01'))))

    def test_padding_length_and_zero_content_are_preserved(self):
        raw = record(extension(21, bytes(17)))
        result = normalize.normalize_wire(raw)
        self.assertEqual(result['padding_extension_length'], 21)
        self.assertEqual(result['handshake_length'] - result['unpadded_hello_length'], 21)
        self.assertEqual(result['extensions'][0]['normalized_data_hex'], '00' * 17)
        self.assertTrue(result['extensions'][0]['all_zero'])

    def test_existing_fixed_chrome_android_captures(self):
        root = next(p for p in Path(__file__).resolve().parents if (p / 'crates/aerobox-crypto/tests/fixtures').is_dir())
        source = root / 'crates/aerobox-crypto/tests/fixtures/utls-reference/captures.json'
        cases = json.loads(source.read_text())
        self.assertEqual(len(cases), 28)
        for case in cases:
            with self.subTest(profile=case['profile'], case=case['case']):
                result = normalize.normalize(case)
                self.assertNotIn('normalization_error', result)
                if 'wire' in result:
                    wire = result['wire']
                    self.assertEqual(len(bytes.fromhex(wire['complete_normalized_record_hex'])), len(bytes.fromhex(case['wire']['record_hex'])))


if __name__ == '__main__':
    unittest.main()
