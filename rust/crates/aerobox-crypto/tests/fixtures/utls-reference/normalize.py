#!/usr/bin/env python3
"""Normalize random ClientHello fields without erasing structural differences."""
import json
import sys


def u16(data):
    return int.from_bytes(data, "big")


def is_grease(value):
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def number(value):
    return "GREASE" if is_grease(value) else f"{value:04x}"


def list16(data):
    return [number(u16(data[i:i + 2])) for i in range(0, len(data), 2)]


def protocols(data):
    data = data[2:]
    output = []
    while data:
        length = data[0]
        output.append(data[1:1 + length].decode("ascii"))
        data = data[1 + length:]
    return output


def normalize(result):
    output = {key: value for key, value in result.items() if key != "wire"}
    wire = result.get("wire")
    if not wire:
        return output
    output["wire"] = normalized = {key: wire[key] for key in (
        "record_type", "record_version", "record_length", "handshake_type",
        "hello_version", "session_id_len", "compression",
    ) if key in wire}
    normalized["ciphers"] = [number(int(value, 16)) for value in wire.get("ciphers", [])]
    normalized["extension_order_is_shuffled"] = result["profile"] == "Chrome-133"
    normalized["extensions"] = extensions = []
    grease_count = 0
    groups = []
    key_shares = []
    for extension in wire.get("extensions", []):
        identity = extension["id"]
        data = bytes.fromhex(extension["hex"])
        parsed = {"id": identity, "length": len(data)}
        if is_grease(identity):
            parsed.update(id=f"GREASE_EXTENSION_{grease_count}", hex=data.hex())
            grease_count += 1
        elif identity in (10, 13):
            parsed["values"] = list16(data[2:])
            if identity == 10:
                groups = [u16(data[i:i + 2]) for i in range(2, len(data), 2)]
        elif identity == 43:
            parsed["versions"] = list16(data[1:])
        elif identity in (16, 17613, 17513):
            parsed["protocols"] = protocols(data)
        elif identity == 51:
            body = data[2:]
            shares = []
            while body:
                group, length = u16(body[:2]), u16(body[2:4])
                public = body[4:4 + length]
                key_shares.append((group, public))
                shares.append({"group": number(group), "length": length,
                               "data": public.hex() if is_grease(group) else "EPHEMERAL_PUBLIC_KEY"})
                body = body[4 + length:]
            parsed["shares"] = shares
        elif identity == 65037 and len(data) > 1:
            enc_length = u16(data[6:8])
            payload_offset = 8 + enc_length
            parsed.update(type=data[0], kdf=f"{u16(data[1:3]):04x}",
                          aead=f"{u16(data[3:5]):04x}", config_id="VARIABLE",
                          encapsulated_key_length=enc_length,
                          encrypted_payload_length=u16(data[payload_offset:payload_offset + 2]))
        else:
            parsed["hex"] = data.hex()
        extensions.append(parsed)
    public_by_group = dict(key_shares)
    if 0x11EC in public_by_group and 29 in public_by_group:
        normalized["hybrid_x25519_equals_standalone"] = public_by_group[0x11EC][-32:] == public_by_group[29]
    if groups and key_shares and is_grease(groups[0]) and is_grease(key_shares[0][0]):
        normalized["grease_group_equals_keyshare"] = groups[0] == key_shares[0][0]
    if result["profile"] == "Android-11":
        normalized["random_and_session_id_zeroed_hex"] = wire.get("normalized_hex")
    return output


if __name__ == "__main__":
    with open(sys.argv[1] if len(sys.argv) > 1 else "captures.json") as source:
        values = json.load(source)
    print(json.dumps([normalize(value) for value in values], indent=2, sort_keys=True))
