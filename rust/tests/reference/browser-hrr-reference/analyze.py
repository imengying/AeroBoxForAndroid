#!/usr/bin/env python3
"""Validate two-flight uTLS HRR captures; preserve byte evidence and slot semantics."""
import json
from pathlib import Path
import sys

from normalize import DecodeError, Reader, grease, normalize_wire

HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')


def require(condition, explanation):
    if not condition:
        raise DecodeError(explanation)


def uint16s(data):
    require(len(data) % 2 == 0, 'odd u16 vector')
    return [int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2)]


def extensions(reader):
    vector = reader.vector(2)
    out = []
    while vector.remaining():
        typ = vector.integer(2)
        out.append((typ, vector.vector(2).data))
    require(len({typ for typ, _ in out}) == len(out), 'duplicate extension')
    reader.done()
    return out


def parse_hello(raw):
    reader = Reader(raw)
    require(reader.integer(1) == 1, 'expected ClientHello')
    require(reader.integer(3) == len(raw) - 4, 'ClientHello length mismatch')
    version = reader.integer(2)
    random = reader.take(32)
    session = reader.vector(1).data
    suites = uint16s(reader.vector(2).data)
    compression = reader.vector(1).data
    prefix = raw[4:reader.pos]
    exts = extensions(reader)
    by_id = dict(exts)
    groups_reader = Reader(by_id[10])
    groups = uint16s(groups_reader.vector(2).data)
    groups_reader.done()
    version_reader = Reader(by_id[43])
    versions = uint16s(version_reader.vector(1).data)
    version_reader.done()
    share_reader = Reader(by_id[51])
    share_vector = share_reader.vector(2)
    shares = []
    while share_vector.remaining():
        group = share_vector.integer(2)
        shares.append((group, share_vector.vector(2).data))
    share_reader.done()
    require(len({group for group, _ in shares}) == len(shares), 'duplicate share group')
    require(all(group in groups for group, _ in shares), 'share group not advertised')
    padding = by_id.get(21)
    require(padding is None or not any(padding), 'nonzero padding bytes')
    padding_length = 0 if padding is None else 4 + len(padding)
    return dict(version=version, random=random, session=session, suites=suites,
                compression=compression, prefix=prefix, extensions=exts,
                groups=groups, versions=versions, shares=shares,
                padding_length=padding_length, unpadded=len(raw) - padding_length)


def parse_hrr(raw):
    reader = Reader(raw)
    require(reader.integer(1) == 2, 'expected HRR ServerHello message')
    require(reader.integer(3) == len(raw) - 4, 'HRR length mismatch')
    require(reader.integer(2) == 0x303, 'HRR legacy version')
    require(reader.take(32) == HRR_RANDOM, 'HRR random')
    session = reader.vector(1).data
    require(reader.integer(2) == 0x1301, 'HRR cipher')
    require(reader.integer(1) == 0, 'HRR compression')
    exts = dict(extensions(reader))
    require(exts.get(43) == b'\x03\x04', 'HRR selected version')
    cookie_reader = Reader(exts[44])
    cookie = cookie_reader.vector(2).data
    cookie_reader.done()
    require(bool(cookie), 'empty HRR cookie')
    return session, cookie, exts


def records(raw):
    reader = Reader(raw)
    out = []
    while reader.remaining():
        typ, version = reader.integer(1), reader.integer(2)
        out.append((typ, version, reader.vector(2).data))
    return out


def validate_grease(hello, expect_share):
    suite_g = [v for v in hello['suites'] if grease(v)]
    group_g = [v for v in hello['groups'] if grease(v)]
    version_g = [v for v in hello['versions'] if grease(v)]
    ext_g = [(v, data) for v, data in hello['extensions'] if grease(v)]
    share_g = [(v, data) for v, data in hello['shares'] if grease(v)]
    require(len(suite_g) == len(group_g) == len(version_g) == 1, 'wrong GREASE slot count')
    require(hello['suites'][0] == suite_g[0], 'GREASE cipher not first')
    require(hello['groups'][0] == group_g[0], 'GREASE group not first')
    require(hello['versions'][0] == version_g[0], 'GREASE version not first')
    require(len(ext_g) == 2 and ext_g[0][0] != ext_g[1][0], 'GREASE extension collision/count')
    require(ext_g[0][1] == b'' and ext_g[1][1] == b'\x00', 'GREASE extension payload')
    if expect_share:
        require(share_g == [(group_g[0], b'\x00')], 'GREASE group/share mismatch')
        require(hello['shares'][0] == share_g[0], 'GREASE share not first')
    else:
        require(not share_g, 'group-changing HRR retained GREASE share')


def validate_firefox(hello, first_flight):
    for values in (hello['suites'], hello['groups'], hello['versions'],
                   [typ for typ, _ in hello['extensions']], [group for group, _ in hello['shares']]):
        require(not any(grease(value) for value in values), 'Firefox unexpectedly has a GREASE slot')
    require(hello['suites'] == [0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9,
            0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c,
            0x009d, 0x002f, 0x0035], 'Firefox cipher order')
    require(hello['groups'] == [29, 23, 24, 25, 256, 257], 'Firefox group order')
    require(hello['versions'] == [0x304, 0x303], 'Firefox version order')
    by_id = dict(hello['extensions'])
    order = [0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 65037]
    if 0 not in by_id:
        order.remove(0)
    require([typ for typ, _ in hello['extensions'] if typ != 44] == order, 'Firefox extension order')
    require(by_id[28] == b'\x40\x01', 'Firefox record size limit')
    require(by_id[34] == bytes.fromhex('00080403050306030203'), 'Firefox DC signatures')
    require(by_id[13] == bytes.fromhex('001604030503060308040805080604010501060102030201'),
            'Firefox handshake signatures')
    require(hello['padding_length'] == 0, 'Firefox unexpectedly has padding')
    if first_flight:
        require([group for group, _ in hello['shares']] == [29, 23], 'Firefox first shares')
        require(len(hello['shares'][0][1]) == 32 and len(hello['shares'][1][1]) == 65
                and hello['shares'][1][1][0] == 4, 'Firefox first share lengths')
    ech = Reader(by_id[65037])
    require(ech.integer(1) == 0 and ech.integer(2) == 1 and ech.integer(2) in (1, 3),
            'Firefox GREASE ECH algorithms')
    ech.integer(1)
    require(len(ech.vector(2).data) == 32 and len(ech.vector(2).data) == 239, 'Firefox GREASE ECH lengths')
    ech.done()


def expected_padding(unpadded):
    if 256 <= unpadded < 512:
        return max(512 - unpadded, 5)
    return 0


def analyze(value):
    metadata = {key: value.get(key) for key in ('source', 'name', 'profile', 'mode', 'case', 'sample')}
    if value.get('skipped_reason'):
        return {**metadata, 'skipped_reason': value['skipped_reason'],
                'second_unpadded_target': value.get('second_unpadded_target')}
    for name in ('build_error', 'panic', 'validation_error'):
        require(not value.get(name), f'{name}: {value.get(name)}')
    require(not value['handshake_complete'], 'capture falsely reports complete handshake')
    require(value['expected_eof'] and bool(value['handshake_error']), 'expected EOF after ClientHello2')
    require(len(value['client_hellos_hex']) == len(value['client_hello_records_hex']) == 2,
            'expected two ClientHello flights')
    raw = [bytes.fromhex(v) for v in value['client_hellos_hex']]
    hellos = [parse_hello(v) for v in raw]
    first, second = hellos
    normalized = []
    for index, encoded in enumerate(value['client_hello_records_hex']):
        wire = bytes.fromhex(encoded)
        recs = records(wire)
        require(all(typ == 22 for typ, _, _ in recs), 'non-handshake record in flight')
        require(b''.join(data for _, _, data in recs) == raw[index], 'flight records do not match message')
        normalized.append(normalize_wire(wire))
    outbound = records(bytes.fromhex(value['outbound_wire_hex']))
    require(b''.join(data for typ, _, data in outbound if typ == 22) == b''.join(raw),
            'outbound capture differs from individual flights')
    require(all(typ in (20, 22) for typ, _, _ in outbound), 'unexpected outbound record type')
    require(all(data == b'\x01' for typ, _, data in outbound if typ == 20), 'bad fake CCS')
    require(first['version'] == second['version'] == 0x303, 'ClientHello legacy version changed')
    require(first['prefix'] == second['prefix'], 'HRR changed random/session/ciphers/compression')
    require(value['built_first_hello_hex'] == raw[0].hex(), 'built first hello differs from wire')
    hrr = bytes.fromhex(value['hrr_handshake_hex'])
    require(records(bytes.fromhex(value['hrr_record_hex'])) == [(22, 0x303, hrr)], 'HRR framing')
    session, cookie, hrr_exts = parse_hrr(hrr)
    require(session == first['session'], 'HRR session mismatch')
    require(cookie.hex() == value['cookie_hex'], 'HRR cookie metadata mismatch')
    second_cookie = Reader(dict(second['extensions'])[44])
    require(second_cookie.vector(2).data == cookie, 'client did not echo cookie exactly')
    second_cookie.done()
    require(44 not in dict(first['extensions']), 'initial hello unexpectedly had a cookie')
    changed_group = value['mode'] == 'cookie-group'
    require(value['mode'] in ('cookie-group', 'cookie-only'), 'unknown HRR mode')
    firefox = value.get('name') == 'firefox'
    group, group_name, point_len = (24, 'P384', 97) if firefox else (23, 'P256', 65)
    if changed_group:
        require(hrr_exts.get(51) == group.to_bytes(2, 'big'), f'missing {group_name} HRR selection')
        require(group in first['groups'] and all(g != group for g, _ in first['shares']), f'HRR {group_name} already offered/unavailable')
        require(len(second['shares']) == 1 and second['shares'][0][0] == group, f'expected only {group_name} after group change')
        point = second['shares'][0][1]
        require(len(point) == point_len and point[0] == 4, f'{group_name} SEC1 share shape')
    else:
        require(51 not in hrr_exts, 'cookie-only HRR selected a group')
        require(first['shares'] == second['shares'], 'cookie-only HRR changed key shares')
    if firefox:
        validate_firefox(first, first_flight=True)
        validate_firefox(second, first_flight=not changed_group)
    else:
        validate_grease(first, expect_share=True)
        validate_grease(second, expect_share=not changed_group)
    allowed_changes = {21, 44, 51}
    require([(typ, data) for typ, data in first['extensions'] if typ not in allowed_changes] ==
            [(typ, data) for typ, data in second['extensions'] if typ not in allowed_changes],
            'HRR changed extension order/content outside cookie, padding, key share')
    before, after = value['objects_before'], value['objects_after']
    before_types, after_types = [v['type'] for v in before], [v['type'] for v in after]
    slots = [i for i, typ in enumerate(after_types) if typ.endswith('.CookieExtension')]
    require(len(slots) == 1, 'expected one new cookie object')
    slot = slots[0]
    require(after_types[:slot] + after_types[slot + 1:] == before_types, 'HRR changed original extension objects')
    require(0 <= slot < len(before) - 2, 'cookie outside pinned uTLS Intn(len(Extensions)-2) range')
    emitted_slot = sum(v['wire_length'] > 0 for v in after[:slot])
    actual_slot = [typ for typ, _ in second['extensions']].index(44)
    require(emitted_slot == actual_slot, 'object-to-wire cookie position mismatch')
    has_padding = any(v.endswith('.UtlsPaddingExtension') for v in before_types)
    require(has_padding == value['has_padding_object'], 'padding object metadata mismatch')
    for hello in hellos:
        expected = expected_padding(hello['unpadded']) if has_padding else 0
        require(hello['padding_length'] == expected, 'padding was not recomputed by BoringPaddingStyle')
    require(second['unpadded'] == value['second_unpadded_hello_length'], 'second unpadded metadata mismatch')
    if value.get('second_unpadded_target'):
        require(second['unpadded'] == value['second_unpadded_target'], 'second padding target mismatch')
    return {**metadata, 'scope': 'two-flight construction only; no authenticated handshake',
            'cookie_object_slot': slot, 'cookie_object_slot_min': 0,
            'cookie_object_slot_max': len(before) - 3, 'cookie_wire_slot': actual_slot,
            'original_object_count': len(before),
            'absent_original_objects': [i for i, v in enumerate(before) if v['wire_length'] == 0],
            'key_share_rule': f'replace with {group_name} only' if changed_group else 'retain exact bytes',
            'flights': normalized, 'valid': True}


def main():
    values = json.loads(Path(sys.argv[1]).read_text())
    result = []
    for value in values:
        try:
            result.append(analyze(value))
        except (DecodeError, KeyError, ValueError, IndexError) as error:
            result.append({'name': value.get('name'), 'mode': value.get('mode'),
                           'case': value.get('case'), 'sample': value.get('sample'),
                           'validation_error': str(error)})
    print(json.dumps(result, indent=2, sort_keys=True))
    if any('validation_error' in item for item in result):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
