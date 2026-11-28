#!/usr/bin/env python3
"""Loopback-only SOCKS5/HTTP peers for exercising the Android VPN on an emulator.

Reserved destinations provide HTTP, UDP echo and synthetic DNS answers.
--public-example additionally forwards example.com:80 (or 203.0.113.11:80)
to example.com. The HTTP peer requires the public test credentials
aerobox-smoke:local-only; the SOCKS peer requires no credentials.
"""
import argparse
import asyncio
import base64
import json
import socket
import struct

PUBLIC_EXAMPLE = False
HTTP_AUTH = b'Basic ' + base64.b64encode(b'aerobox-smoke:local-only')


def event(kind, **fields):
    print(json.dumps({'event': kind, **fields}), flush=True)


def dns_answer(message):
    """Answer simple A/AAAA questions for *.smoke.invalid without external DNS."""
    if len(message) < 17 or message[4:6] != b'\x00\x01':
        raise ValueError('expected one DNS question')
    pos, labels = 12, []
    while message[pos]:
        length = message[pos]
        if length > 63 or pos + length + 1 >= len(message):
            raise ValueError('invalid DNS label')
        labels.append(message[pos + 1:pos + 1 + length].decode('ascii'))
        pos += length + 1
    end = pos + 5
    qtype, qclass = struct.unpack('!HH', message[pos + 1:end])
    name = '.'.join(labels).lower()
    public = PUBLIC_EXAMPLE and name == 'example.com'
    known = public or name == 'smoke.invalid' or name.endswith('.smoke.invalid')
    has_answer = known and qtype == 1 and qclass == 1
    header = message[:2] + struct.pack('!HHHHH', 0x8180 if known else 0x8183, 1, int(has_answer), 0, 0)
    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton('203.0.113.11' if public else '203.0.113.10') if has_answer else b''
    event('dns', name=name, qtype=qtype, answer=has_answer)
    return header + message[12:end] + answer


def destination(host, port):
    if port == 18080 and (host == '203.0.113.10' or host == 'smoke.invalid' or host.endswith('.smoke.invalid')):
        return 'marker'
    if host == '203.0.113.53' and port == 53:
        return 'dns'
    if PUBLIC_EXAMPLE and host in ('example.com', '203.0.113.11') and port == 80:
        return 'public'
    return None


async def serve_destination(reader, writer, kind, protocol, host, port):
    if kind == 'dns':
        while True:
            size = int.from_bytes(await reader.readexactly(2), 'big')
            answer = dns_answer(await reader.readexactly(size))
            writer.write(len(answer).to_bytes(2, 'big') + answer)
            await writer.drain()
    header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 15)
    if kind == 'public':
        event('public-start', protocol=protocol, target=host, port=port)
        remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection('example.com', 80, family=socket.AF_INET, happy_eyeballs_delay=0.25), 10)
        total = 0
        try:
            remote_writer.write(header)
            await remote_writer.drain()
            while chunk := await asyncio.wait_for(remote_reader.read(16384), 15):
                total += len(chunk)
                if total > 1024 * 1024:
                    raise ValueError('public test response exceeded limit')
                writer.write(chunk)
                await writer.drain()
        finally:
            remote_writer.close()
            await remote_writer.wait_closed()
        event('public-http', protocol=protocol, upstream='example.com:80', bytes=total)
        return
    body = b'AEROBOX_RUST_ANDROID_VPN_OK\n'
    writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    await writer.drain()
    event('http-through-' + protocol, target=host, port=port, request_bytes=len(header), response_bytes=len(body))


async def http_client(reader, writer):
    try:
        header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 15)
        request, *lines = header.split(b'\r\n')
        method, authority, version = request.split(b' ')
        fields = {key.strip().lower(): value.strip() for line in lines if b':' in line for key, value in [line.split(b':', 1)]}
        if fields.get(b'proxy-authorization') != HTTP_AUTH:
            writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="local-smoke"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            await writer.drain()
            event('http-auth-rejected')
            return
        host, port = authority.decode('ascii').rsplit(':', 1)
        port = int(port)
        kind = destination(host, port)
        if method != b'CONNECT' or version != b'HTTP/1.1' or not kind:
            writer.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            await writer.drain()
            return
        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        await writer.drain()
        event('http-connect', target=host, port=port, authenticated=True)
        await serve_destination(reader, writer, kind, 'http-connect', host, port)
    except (asyncio.IncompleteReadError, OSError, TimeoutError, ValueError, IndexError, struct.error) as error:
        event('peer-error', error=type(error).__name__, detail=str(error))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


class UdpPeer(asyncio.DatagramProtocol):
    def __init__(self, socks=False):
        self.socks = socks

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, packet, source):
        try:
            header = b''
            host, port = '203.0.113.53', 53
            if self.socks:
                if packet[:3] != b'\x00\x00\x00':
                    return
                kind, pos = packet[3], 4
                if kind == 1:
                    host = socket.inet_ntop(socket.AF_INET, packet[pos:pos + 4]); pos += 4
                elif kind == 3:
                    length = packet[pos]; pos += 1
                    host = packet[pos:pos + length].decode('ascii'); pos += length
                elif kind == 4:
                    host = socket.inet_ntop(socket.AF_INET6, packet[pos:pos + 16]); pos += 16
                else:
                    return
                port = int.from_bytes(packet[pos:pos + 2], 'big'); pos += 2
                header, packet = packet[:pos], packet[pos:]
            if host == '203.0.113.53' and port == 53:
                reply = dns_answer(packet)
            elif self.socks and host == '203.0.113.10' and port == 18082:
                reply = packet
                event('udp-through-socks', bytes=len(packet))
            else:
                event('udp-rejected', target=host, port=port)
                return
            self.transport.sendto(header + reply, source)
        except (ValueError, IndexError, struct.error, UnicodeError, OSError):
            return


async def client(reader, writer):
    udp = None
    try:
        version, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        if version != 5 or 0 not in methods:
            return
        writer.write(b'\x05\x00')
        await writer.drain()
        version, command, reserved, kind = await reader.readexactly(4)
        if kind == 1:
            host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
        elif kind == 3:
            host = (await reader.readexactly((await reader.readexactly(1))[0])).decode('ascii')
        elif kind == 4:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            return
        port = int.from_bytes(await reader.readexactly(2), 'big')
        if version != 5 or reserved != 0:
            return
        if command == 3:
            udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: UdpPeer(socks=True), local_addr=('127.0.0.1', 0))
            relay_port = udp.get_extra_info('sockname')[1]
            # Unspecified address makes the client use the SOCKS server address,
            # which is 10.0.2.2 inside the emulator, rather than its own loopback.
            writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00' + relay_port.to_bytes(2, 'big'))
            await writer.drain()
            await reader.read(1)
            return
        kind = destination(host, port)
        allowed = command == 1 and kind is not None
        writer.write(bytes([5, 0 if allowed else 2, 0, 1, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
        if not allowed:
            event('rejected', command=command, target=host, port=port)
            return
        await serve_destination(reader, writer, kind, 'socks', host, port)
    except (asyncio.IncompleteReadError, OSError, TimeoutError, ValueError, IndexError, struct.error) as error:
        event('peer-error', error=type(error).__name__, detail=str(error))
    finally:
        if udp:
            udp.close()
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


async def main():
    server = await asyncio.start_server(client, '127.0.0.1', 18081, limit=16384)
    http = await asyncio.start_server(http_client, '127.0.0.1', 18083, limit=16384)
    dns, _ = await asyncio.get_running_loop().create_datagram_endpoint(UdpPeer, local_addr=('127.0.0.1', 18053))
    event('listen', socks='127.0.0.1:18081', http='127.0.0.1:18083', direct_dns='127.0.0.1:18053', public_example=PUBLIC_EXAMPLE)
    try:
        async with server, http:
            await asyncio.gather(server.serve_forever(), http.serve_forever())
    finally:
        dns.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-example', action='store_true')
    PUBLIC_EXAMPLE = parser.parse_args().public_example
    asyncio.run(main())
