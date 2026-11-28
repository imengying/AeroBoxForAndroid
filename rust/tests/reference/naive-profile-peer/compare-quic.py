#!/usr/bin/env python3
"""Compare authenticated QUIC Initial captures; report H3/transport gaps separately.

Input ClientHellos are decrypted/reassembled by the independent Go observer.
Only the parser receives a synthetic TLS record envelope. QUIC has no TLS records.
This validates TLS structure and CONNECT semantics, not a complete QUIC fingerprint.
"""
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location(
    "tls_parser", Path(__file__).resolve().parent.parent / "browser-profile-reference/normalize.py")
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


def varint(reader):
    first = reader.integer(1)
    width = 1 << (first >> 6)
    return ((first & 63) << (8 * (width - 1))) | reader.integer(width - 1)


def parameters(data):
    reader = parser.Reader(data)
    fields = []
    seen = set()
    while reader.remaining():
        key = varint(reader)
        size = varint(reader)
        value = reader.take(size)
        if key in seen:
            raise ValueError("duplicate QUIC transport parameter")
        seen.add(key)
        if key in (0, 2, 15, 16):
            value = {"byte_length": len(value)}  # Random connection IDs/reset token.
        elif key in (1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 32):
            number = parser.Reader(value)
            value = varint(number)
            number.done()
        else:
            value = value.hex()
        fields.append({"id": key, "value": value})
    return fields


def tls(directory):
    raw = (directory / "client-hello.bin").read_bytes()
    if not 4 <= len(raw) <= 65535:
        raise ValueError("invalid ClientHello size")
    hello = parser.normalize_wire(b"\x16\x03\x01" + len(raw).to_bytes(2, "big") + raw)
    fields = {}
    transport = None
    for extension in hello["extensions"]:
        item = dict(extension)
        key = item.pop("id")
        if key in fields or key.startswith("GREASE_"):
            raise ValueError("duplicate extension or unexpected TCP GREASE slot")
        if key == "0039":
            transport = parameters(bytes.fromhex(item["normalized_data_hex"]))
            continue
        if key == "fe0d":
            if item["payload_length"] not in (144, 176, 208, 240):
                raise ValueError("unexpected GREASE ECH payload length")
            for field in ("length", "payload_length", "normalized_data_hex"):
                del item[field]
        fields[key] = item
    if transport is None:
        raise ValueError("missing QUIC transport parameters")
    shape = {key: hello[key] for key in ("hello_version", "session_id_length", "compression", "ciphers",
                                        "all_share_groups_advertised", "hybrid_x25519_equals_standalone")}
    shape["extensions"] = fields
    return shape, transport


def h3(directory, require_fin):
    capture = json.loads((directory / "capture.json").read_text())
    if capture["phase"] != "complete" or capture["requests"] != 2:
        raise ValueError("capture did not complete two tunnels")
    settings = None
    requests = []
    details = []
    for entry in capture["streams"]:
        if entry["ID"] % 4 == 2 and entry["Type"] == 4:
            if settings is not None:
                raise ValueError("duplicate SETTINGS")
            reader = parser.Reader(bytes.fromhex(entry["Data"]))
            settings = []
            while reader.remaining():
                settings.append([varint(reader), varint(reader)])
        if entry["Headers"] is not None:
            fields = [dict(field) for field in entry["Headers"]]
            if entry["Bytes"] < 65537 or (require_fin and entry.get("End") != "fin"):
                raise ValueError("missing data or clean Rust FIN")
            for field in fields:
                if field["Name"] == "padding":
                    value = field["Value"]
                    if not (30 <= len(value) <= 61 and all(c in "!#$()+<>?@[]^`{}" for c in value[:16])
                            and set(value[16:]) == {"~"}):
                        raise ValueError("invalid Naive padding header")
                    field["Value"] = "<random padding>"
            requests.append({"stream": entry["ID"], "headers": sorted(fields, key=lambda f: f["Name"])})
            details.append({"stream": entry["ID"], "header_order": [f["Name"] for f in fields],
                            "qpack_hex": entry["Data"], "padded_bytes": entry["Bytes"], "end": entry.get("End")})
    if settings is None or len(requests) != 2:
        raise ValueError("missing SETTINGS or CONNECT")
    return requests, {"settings": settings, "requests": details}


def main():
    reference, actual, output = map(Path, sys.argv[1:])
    normalized = []
    for directory, require_fin in [(reference, False), (actual, True)]:
        hello, transport = tls(directory)
        requests, details = h3(directory, require_fin)
        normalized.append({"tls_without_transport_parameters": hello, "connect_semantics": requests,
                           "transport_parameters": transport, "h3_wire": details})
    checked = ("tls_without_transport_parameters", "connect_semantics")
    differences = [key for key in checked if normalized[0][key] != normalized[1][key]]
    remaining = [key for key in ("transport_parameters", "h3_wire") if normalized[0][key] != normalized[1][key]]
    output.write_text(json.dumps({"reference": str(reference), "actual": str(actual),
                                  "checked_differences": differences, "remaining_wire_differences": remaining,
                                  "normalized": normalized}, indent=2) + "\n")
    print("Naive QUIC TLS/CONNECT check:", "PASS" if not differences else str(differences))
    print("Remaining QUIC/H3 wire differences:", ", ".join(remaining) or "none in this sample")
    return bool(differences)


if __name__ == "__main__":
    sys.exit(main())
