#!/usr/bin/env python3
"""Normalize only randomness; retain complete TLS bytes, lengths and field order."""
import json
import sys

MAX_CAPTURE = 1 << 20


class DecodeError(ValueError):
    pass


class Reader:
    def __init__(self, data, base=0):
        self.data = data
        self.pos = 0
        self.base = base

    def take(self, size):
        if size < 0 or self.pos + size > len(self.data):
            raise DecodeError(f'truncated vector at {self.base + self.pos}, requested {size}')
        value = self.data[self.pos:self.pos + size]
        self.pos += size
        return value

    def integer(self, size):
        return int.from_bytes(self.take(size), 'big')

    def vector(self, length_bytes):
        size = self.integer(length_bytes)
        offset = self.base + self.pos
        return Reader(self.take(size), offset)

    def done(self):
        if self.pos != len(self.data):
            raise DecodeError(f'trailing bytes at {self.base + self.pos}')

    def remaining(self):
        return len(self.data) - self.pos


def grease(value):
    return value & 0x0f0f == 0x0a0a and value >> 8 == value & 255


def normalize_wire(raw):
    if not raw or len(raw) > MAX_CAPTURE:
        raise DecodeError('empty or over-limit capture')
    wire = Reader(raw)
    normalized = bytearray(raw)
    records = []
    handshake_positions = []
    handshake_bytes = bytearray()
    while wire.remaining():
        record_offset = wire.pos
        typ, version, length = wire.integer(1), wire.integer(2), wire.integer(2)
        payload_offset = wire.pos
        payload = wire.take(length)
        records.append({'type': typ, 'version': f'{version:04x}', 'length': length, 'offset': record_offset})
        if typ == 22:
            handshake_bytes.extend(payload)
            handshake_positions.extend(range(payload_offset, payload_offset + length))
    if len(handshake_bytes) < 4 or handshake_bytes[0] != 1:
        raise DecodeError('no initial ClientHello')
    hello_length = 4 + int.from_bytes(handshake_bytes[1:4], 'big')
    if len(handshake_bytes) != hello_length:
        raise DecodeError('incomplete ClientHello or additional unexpected handshake bytes')
    hello = Reader(handshake_bytes)
    hello.take(4)
    hello_version = hello.integer(2)

    def rewrite(offset, data):
        for i, byte in enumerate(data):
            normalized[handshake_positions[offset + i]] = byte

    # Preserve random and session-id lengths but erase their entropy.
    rewrite(hello.pos, bytes(32))
    hello.take(32)
    session_id = hello.vector(1)
    rewrite(session_id.base, bytes(len(session_id.data)))
    aliases = {}
    occurrences = []

    def identity(value, offset, field):
        if grease(value):
            index = aliases.setdefault(value, len(aliases))
            canonical = 0x0a0a + index * 0x1010
            rewrite(offset, canonical.to_bytes(2, 'big'))
            occurrences.append({'field': field, 'class': index})
            return f'GREASE_{index}'
        return f'{value:04x}'

    def ids(vector, field):
        if len(vector.data) % 2:
            raise DecodeError('odd uint16 vector')
        values = []
        while vector.remaining():
            offset = vector.base + vector.pos
            values.append(identity(vector.integer(2), offset, f'{field}[{len(values)}]'))
        return values

    suites = ids(hello.vector(2), 'cipher')
    compression = hello.vector(1).data.hex()
    extensions = []
    groups = []
    shares = []
    padding_length = 0
    if hello.remaining():
        extension_vector = hello.vector(2)
        while extension_vector.remaining():
            offset = extension_vector.base + extension_vector.pos
            ext_id = extension_vector.integer(2)
            data = extension_vector.vector(2)
            fields = {'id': identity(ext_id, offset, f'extension[{len(extensions)}]'), 'length': len(data.data)}
            if grease(ext_id):
                pass
            elif ext_id in (10, 13, 34):
                child = data.vector(2)
                fields['values'] = ids(child, f'extension-{ext_id}')
                if ext_id == 10:
                    groups = [int.from_bytes(child.data[i:i + 2], 'big') for i in range(0, len(child.data), 2)]
                data.done()
            elif ext_id == 43:
                fields['versions'] = ids(data.vector(1), 'supported_version')
                data.done()
            elif ext_id in (16, 17513, 17613):
                protocols = data.vector(2)
                fields['protocols_hex'] = []
                while protocols.remaining():
                    fields['protocols_hex'].append(protocols.vector(1).data.hex())
                data.done()
            elif ext_id == 0:
                names = data.vector(2)
                fields['names'] = []
                while names.remaining():
                    typ = names.integer(1)
                    fields['names'].append({'type': typ, 'name_hex': names.vector(2).data.hex()})
                data.done()
            elif ext_id == 51:
                vector = data.vector(2)
                fields['shares'] = []
                while vector.remaining():
                    group_offset = vector.base + vector.pos
                    group = vector.integer(2)
                    public = vector.vector(2)
                    group_name = identity(group, group_offset, f'key_share[{len(shares)}]')
                    fields['shares'].append({'group': group_name, 'length': len(public.data)})
                    shares.append((group, bytes(public.data)))
                    if not grease(group):
                        # SEC1 point-format byte is structural, not randomness.
                        fixed = 1 if group in (23, 24, 25) and public.data else 0
                        rewrite(public.base + fixed, bytes(len(public.data) - fixed))
                data.done()
            elif ext_id == 65037:
                typ = data.integer(1)
                fields['type'] = typ
                if typ == 0:
                    fields['kdf'], fields['aead'] = f'{data.integer(2):04x}', f'{data.integer(2):04x}'
                    rewrite(data.base + data.pos, b'\0')
                    data.take(1)
                    encapsulated = data.vector(2)
                    rewrite(encapsulated.base, bytes(len(encapsulated.data)))
                    payload = data.vector(2)
                    rewrite(payload.base, bytes(len(payload.data)))
                    fields['encapsulated_key_length'] = len(encapsulated.data)
                    fields['payload_length'] = len(payload.data)
                data.done()
            elif ext_id == 21:
                fields['all_zero'] = not any(data.data)
                padding_length += 4 + len(data.data)
            elif ext_id == 28:
                fields['record_size_limit'] = data.integer(2)
                data.done()
            elif ext_id == 27:
                fields['compression_algorithms'] = ids(data.vector(1), 'certificate_compression')
                data.done()
            # Retain every payload byte after only the precise random-field
            # redactions above, including unknown extensions and empty vectors.
            fields['normalized_data_hex'] = bytes(normalized[handshake_positions[data.base + i]] for i in range(len(data.data))).hex()
            extensions.append(fields)
    hello.done()
    public_by_group = dict(shares)
    result = {
        'records': records,
        'handshake_length': hello_length,
        'hello_version': f'{hello_version:04x}',
        'session_id_length': len(session_id.data),
        'compression': compression,
        'ciphers': suites,
        'extensions': extensions,
        'grease_equivalence_classes': occurrences,
        'unpadded_hello_length': hello_length - padding_length,
        'padding_extension_length': padding_length,
        'all_share_groups_advertised': all(group in groups for group, _ in shares),
        'complete_normalized_record_hex': normalized.hex(),
    }
    if 4588 in public_by_group and 29 in public_by_group:
        result['hybrid_x25519_equals_standalone'] = public_by_group[4588][-32:] == public_by_group[29]
    return result


def normalize(result):
    output = {k: v for k, v in result.items() if k not in ('wire_hex', 'built_client_hello_hex', 'wire')}
    # Also supports read-only checks against the existing Chrome/Android fixture.
    wire_hex = result.get('wire_hex') or result.get('wire', {}).get('record_hex')
    if not wire_hex:
        return output
    try:
        output['wire'] = normalize_wire(bytes.fromhex(wire_hex))
        for name in ('unpadded_hello_length', 'padding_extension_length'):
            if name in result and result[name] != output['wire'][name]:
                raise DecodeError(f'Go metadata differs from wire: {name}')
    except (ValueError, IndexError) as error:
        output['normalization_error'] = str(error)
    output['extension_order_is_shuffled'] = result.get('profile') == 'Chrome-133'
    return output


def main():
    with open(sys.argv[1] if len(sys.argv) > 1 else 'captures.json') as source:
        values = json.load(source)
    result = [normalize(value) for value in values]
    print(json.dumps(result, indent=2, sort_keys=True))
    if any('normalization_error' in value for value in result):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
