#!/usr/bin/env python3
"""Inspect defined DEX methods after R8; do not load the Android native library."""
import json
import struct
import sys
import zipfile

CALLBACK = 'Lcom/aerobox/core/native/RustCoreNative$PlatformCallbacks;'
NATIVE = 'Lcom/aerobox/core/native/RustCoreNative;'
CALLBACKS = {
    'protect': '(I)Z',
    'dnsServers': '()Ljava/lang/String;',
    'supportsSystemDns': '()Z',
    'startDnsQuery': '(JJJ[B)V',
    'cancelDnsQuery': '(J)V',
    'connectionOwner': '(ILjava/lang/String;ILjava/lang/String;I)Ljava/lang/String;',
    'physicalNetworks': '()Ljava/lang/String;',
    'protectOnNetwork': '(IJJ)Z',
}
STRING = 'Ljava/lang/String;'
NATIVES = {
    'nativeInit': f'({STRING}){STRING}',
    'nativeCheck': f'({STRING}){STRING}',
    'nativeStart': f'({STRING}I{CALLBACK}){STRING}',
    'nativeStop': f'(){STRING}',
    'nativeNetworkChanged': f'(){STRING}',
    'nativeIsRunning': f'(){STRING}',
    'nativeStats': f'(){STRING}',
    'nativeConnections': f'(){STRING}',
    'nativeCloseConnection': f'({STRING}){STRING}',
    'nativeUrlTestConfig': f'({STRING}{STRING}{STRING}J{CALLBACK}){STRING}',
    'nativeDrainLogs': f'(){STRING}',
    'nativeDnsQueryComplete': f'(J[BII{STRING})V',
}


def classes(data):
    assert data[:4] == b'dex\n'
    u32 = lambda offset: struct.unpack_from('<I', data, offset)[0]
    u16 = lambda offset: struct.unpack_from('<H', data, offset)[0]

    def uleb(offset):
        result = 0
        for shift in range(0, 35, 7):
            value = data[offset]
            offset += 1
            result |= (value & 0x7f) << shift
            if value < 0x80:
                return result, offset
        raise ValueError('invalid ULEB128')

    def string(index):
        pointer = u32(u32(60) + index * 4)
        _, pointer = uleb(pointer)
        return data[pointer:data.index(0, pointer)].decode('utf-8', errors='replace')

    def typ(index):
        return string(u32(u32(68) + index * 4))

    def types(offset):
        return [] if not offset else [typ(u16(offset + 4 + i * 2)) for i in range(u32(offset))]

    def method(index):
        pointer = u32(92) + index * 8
        proto = u32(76) + u16(pointer + 2) * 12
        descriptor = '(' + ''.join(types(u32(proto + 8))) + ')' + typ(u32(proto + 4))
        return string(u32(pointer + 4)), descriptor

    for index in range(u32(96)):
        pointer = u32(100) + index * 32
        name, interfaces = typ(u32(pointer)), types(u32(pointer + 12))
        if name not in (CALLBACK, NATIVE) and CALLBACK not in interfaces:
            continue
        pointer = u32(pointer + 24)
        counts = []
        for _ in range(4):
            count, pointer = uleb(pointer)
            counts.append(count)
        for _ in range(counts[0] + counts[1]):
            _, pointer = uleb(pointer)
            _, pointer = uleb(pointer)
        methods = {}
        for count in counts[2:]:
            method_index = 0
            for _ in range(count):
                diff, pointer = uleb(pointer)
                method_index += diff
                access, pointer = uleb(pointer)
                _, pointer = uleb(pointer)
                method_name, descriptor = method(method_index)
                methods[method_name] = {'descriptor': descriptor, 'access_flags': access}
        yield name, methods


result = {}
with zipfile.ZipFile(sys.argv[1]) as apk:
    for member in apk.namelist():
        if member.startswith('classes') and member.endswith('.dex'):
            result.update(classes(apk.read(member)))
assert CALLBACK in result and NATIVE in result
for name, methods in result.items():
    if name == NATIVE:
        actual = {method for method, info in methods.items() if info['access_flags'] & 0x100}
        assert actual == NATIVES.keys(), ('native methods', actual ^ NATIVES.keys())
        for native, descriptor in NATIVES.items():
            assert methods[native]['descriptor'] == descriptor, (native, 'signature changed')
            assert methods[native]['access_flags'] & 0x8, (native, 'not static')
        continue
    for callback, descriptor in CALLBACKS.items():
        assert methods[callback]['descriptor'] == descriptor, (name, callback)
        assert methods[callback]['access_flags'] & 1, (name, callback, 'not public')
assert len(result) >= 4, 'expected interface, two concrete callbacks, and native bridge'
print(json.dumps({'apk': sys.argv[1], 'defined_jni_classes': result}, indent=2))
