#!/usr/bin/env python3
"""Compare captured Naive TCP first flights and CONNECT fields with pinned Cronet.

Random extension order, key material, GREASE values and padding are checked by
shape. This does not assert equivalence of packet timing or complete Chromium.
"""
import importlib.util
import json
from pathlib import Path
import sys

parser_path = Path(__file__).resolve().parent.parent / "browser-profile-reference/normalize.py"
spec = importlib.util.spec_from_file_location("tls_normalize", parser_path)
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


def first_flight(raw):
    wire = parser.Reader(raw)
    records = bytearray()
    hello = bytearray()
    while wire.remaining():
        start = wire.pos
        kind, _version, length = wire.integer(1), wire.integer(2), wire.integer(2)
        data = wire.take(length)
        if kind != 22:
            raise ValueError("non-handshake record before complete ClientHello")
        records.extend(raw[start:wire.pos])
        hello.extend(data)
        if len(hello) >= 4 and len(hello) == 4 + int.from_bytes(hello[1:4], "big"):
            return parser.normalize_wire(bytes(records))
    raise ValueError("incomplete ClientHello")


def grease_id(value):
    return "GREASE" if value.startswith("GREASE_") else value


def tls_shape(path):
    hello = first_flight(path.read_bytes())
    extensions = {}
    grease = []
    ech_length = 0
    for position, source in enumerate(hello["extensions"]):
        item = dict(source)
        kind = item.pop("id")
        if kind.startswith("GREASE_"):
            grease.append({"position": position, "data": item["normalized_data_hex"]})
            continue
        if kind in extensions:
            raise ValueError("duplicate TLS extension")
        if kind in ("000a", "002b", "0033"):
            del item["normalized_data_hex"]
        for field in ("values", "versions"):
            if field in item:
                item[field] = [grease_id(value) for value in item[field]]
        if "shares" in item:
            item["shares"] = [{**share, "group": grease_id(share["group"])} for share in item["shares"]]
        if kind == "fe0d":
            ech_length = item.pop("length")
            length = item.pop("payload_length")
            if length not in (144, 176, 208, 240):
                raise ValueError("unexpected GREASE ECH payload length")
            del item["normalized_data_hex"]
        extensions[kind] = item
    return {
        "ciphers": [grease_id(value) for value in hello["ciphers"]],
        "hello_version": hello["hello_version"],
        "session_id_length": hello["session_id_length"],
        "compression": hello["compression"],
        "length_without_ech_payload": hello["handshake_length"] - ech_length,
        "record_versions": [record["version"] for record in hello["records"]],
        "hybrid_x25519_equals_standalone": hello["hybrid_x25519_equals_standalone"],
        "all_share_groups_advertised": hello["all_share_groups_advertised"],
        "grease_extensions": grease,
        "extensions": extensions,
    }


def h2_shape(path):
    capture = json.loads(path.read_text())
    if capture["requests"] != 2:
        raise ValueError("capture must complete two tunnels")
    frames = capture["frames"]
    result = {"settings": next(f["Settings"] for f in frames if f["Type"] == "SETTINGS" and f["Flags"] == 0),
              "window": next(f["Payload"] for f in frames if f["Type"] == "WINDOW_UPDATE" and f["Stream"] == 0),
              "connect": []}
    for frame in (f for f in frames if f["Type"] == "HEADERS"):
        fields = [dict(field) for field in frame["Headers"]]
        if [field["Name"] for field in fields[:2]] != [":method", ":authority"]:
            raise ValueError("wrong CONNECT pseudo-header order")
        if fields[-1]["Name"] != "user-agent":
            raise ValueError("user-agent must follow the extra headers")
        for field in fields:
            if field["Name"] == "padding":
                padding = field["Value"]
                if not (30 <= len(padding) <= 61 and all(c in "!#$()+<>?@[]^`{}" for c in padding[:16]) and set(padding[16:]) == {"~"}):
                    raise ValueError("unexpected Naive padding")
                field["Value"] = "<random padding>"
        encoded = bytes.fromhex(frame["Payload"])
        # A peer SETTINGS change can precede the next CONNECT with a table-size update.
        offset = 0
        while encoded[offset] & 0xe0 == 0x20:
            first = encoded[offset]
            offset += 1
            if first & 0x1f == 0x1f:
                while encoded[offset] & 0x80:
                    offset += 1
                offset += 1
        if encoded[offset:offset + 9] != b"\x02\x07CONNECT":
            raise ValueError("CONNECT must use a literal, non-Huffman, non-indexing value")
        result["connect"].append({"stream": frame["Stream"], "flags": frame["Flags"],
                                  "priority": frame["Priority"],
                                  "authority_indexed": bool(encoded[offset + 9] & 0x80),
                                  "headers": sorted(fields, key=lambda f: f["Name"])})
    if len(result["connect"]) != 2:
        raise ValueError("capture must contain two CONNECT streams")
    return result


def main():
    reference, actual, output = map(Path, sys.argv[1:])
    captures = [{"tls": tls_shape(path / "client-tls.bin"), "h2": h2_shape(path / "capture.json")}
                for path in (reference, actual)]
    differences = [section for section in ("tls", "h2") if captures[0][section] != captures[1][section]]
    output.write_text(json.dumps({"reference": str(reference), "actual": str(actual),
                                  "differences": differences, "normalized": captures}, indent=2) + "\n")
    print("Naive TCP reference comparison:", "PASS" if not differences else ", ".join(differences) + " differ")
    return bool(differences)


if __name__ == "__main__":
    sys.exit(main())
