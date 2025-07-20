import asyncio
import socket
import struct
import random

STUN_SERVERS = [
    {'host': 'stun1.l.google.com', 'port': 19302},
    {'host': 'stun2.l.google.com', 'port': 19302},
    {'host': 'stun3.l.google.com', 'port': 19302},
    {'host': 'stun4.l.google.com', 'port': 19302},
    {'host': 'stun.cloudflare.com'},
    {'host': 'stun.1und1.de'},
]
MAGIC_COOKIE = 0x2112A442


def build_stun_request(change_ip=False, change_port=False) -> bytes:
    """
    Build a STUN Binding Request (RFC 3489) with optional CHANGE-REQUEST.
    """
    msg_type = 0x0001  # Binding Request
    transaction_id = random.randbytes(12)
    attrs = b''
    if change_ip or change_port:
        flags = 0
        if change_ip: flags |= 0x04
        if change_port: flags |= 0x02
        # CHANGE-REQUEST attr: type=0x0003, length=4
        attrs = struct.pack('!HHI', 0x0003, 4, flags)
    msg_length = len(attrs)
    header = struct.pack('!HHI12s', msg_type, msg_length, MAGIC_COOKIE, transaction_id)
    return header + attrs


def parse_mapped_or_xor_address(data: bytes) -> tuple[str,int]:
    """
    RG3489: MAPPED‑ADDRESS (0x0001)
    RFC5389: XOR‑MAPPED‑ADDRESS (0x0020)
    """
    if len(data) < 20:
        print(data)
        raise ValueError("STUN response too short")
    msg_len = struct.unpack('!H', data[2:4])[0]
    offset = 20
    end = offset + msg_len

    mapped = None
    while offset + 4 <= end:
        t, l = struct.unpack('!HH', data[offset:offset+4])
        offset += 4
        v = data[offset:offset+l]
        offset += l
        if l % 4:
            offset += (4 - (l % 4))

        # RFC3489 MAPPED‑ADDRESS
        if t == 0x0001:
            # v: [0] = 0, [1]=family, [2:4]=port, [4:8]=IPv4
            port = struct.unpack('!H', v[2:4])[0]
            ip   = socket.inet_ntoa(v[4:8])
            mapped = (ip, port)
            # aber weitersuchen, vielleicht gibt's XOR noch
        # RFC5389 XOR‑MAPPED‑ADDRESS
        elif t == 0x0020:
            xport = struct.unpack('!H', v[2:4])[0] ^ (MAGIC_COOKIE >> 16)
            xip   = struct.unpack('!I', v[4:8])[0] ^ MAGIC_COOKIE
            ip    = socket.inet_ntoa(struct.pack('!I', xip))
            return ip, xport

    if mapped:
        return mapped

    raise RuntimeError("Mapped‑Address nicht gefunden")


class STUNProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future):
        self.future = future

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result((data, addr))

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_exception(exc)


async def send_stun(server: dict, timeout: float = 1.0, change_ip=False, change_port=False) -> tuple[bytes, tuple[str,int]]:
    req = build_stun_request(change_ip=change_ip, change_port=change_port)
    print("REQUEST-HEX:", req.hex())

    # 1) UDP‑Socket anlegen (kein connect, keine asyncio‑Magic)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        # 2) Abschicken
        dst = (server['host'], server.get('port', 3478))
        sock.sendto(req, dst)

        # 3) Warten auf erste Antwort
        data, addr = sock.recvfrom(2048)
        return data, addr

    finally:
        sock.close()



async def get_external_address(server: dict, timeout: float = 1.0, change_ip=False, change_port=False) -> tuple[
    str, int]:
    data, _ = await send_stun(server, timeout, change_ip, change_port)
    return parse_mapped_or_xor_address(data)


async def detect_nat_type() -> str:
    stun1 = STUN_SERVERS[5]
    stun2 = STUN_SERVERS[4]

    # Test I: Binding Request an Server1
    try:
        ext1 = await get_external_address(stun1)
        print_external_address_response(stun1, ext1)
    except Exception:
        print("Test I: Keine Antwort → UDP Blocked")
        return "UDP Blocked"

    # Test II: Change IP & Port an Server1
    try:
        ext2 = await get_external_address(stun1, change_ip=True, change_port=True)
        print_external_address_response(stun1, ext2)
        print("Test II: Change IP & Port → Antwort erhalten")
        return "Full Cone NAT"
    except Exception:
        print("Test II: Change IP & Port → keine Antwort")

    # Test I erneut, aber an Server2
    try:
        ext3 = await get_external_address(stun2)
        print_external_address_response(stun2, ext3)
    except Exception:
        print("Test I (Server2): Keine Antwort → Symmetric UDP Firewall")
        return "Symmetric UDP Firewall"

    # Mapping-Vergleich
    if ext1 != ext3:
        return "Symmetric NAT"

    # Test III: Change Port an Server1
    try:
        await send_stun(stun1, change_ip=False, change_port=True)
        print("Test III: Change Port → Antwort erhalten")
        return "Restricted NAT"
    except Exception:
        print("Test III: Change Port → keine Antwort")
        return "Port Restricted NAT"


def print_external_address_response(server: dict, response: tuple[str, int]):
    print(f"External via {server['host']}:{server.get('port', 3478)} → {response[0]}:{response[1]}")


async def check_change_flags(server):
    # Test I
    try:
        data1, addr1 = await send_stun(server, timeout=1.0,
                                      change_ip=False, change_port=False)
        print("Antwort von", addr1, "→", parse_mapped_or_xor_address(data1))
    except Exception as e:
        print("Kein Reply ohne Flags:", e)

    # Test II (CHANGE-REQUEST)
    try:
        data2, addr2 = await send_stun(server, timeout=1.0,
                                      change_ip=True, change_port=True)
        print("Antwort von", addr2, "→", parse_mapped_or_xor_address(data2))
    except Exception as e:
        print("Kein Reply mit CHANGE-REQUEST:", e)

async def main():
    # print(await detect_nat_type())
    # await check_change_flags({'host': 'stun1.l.google.com', 'port': 19302})
    await check_change_flags({'host': 'stun.12voip.com', 'port': 3478})
    # await check_change_flags({'host': 'stun.ekiga.net', 'port': 3478})
    # await check_change_flags({'host': 'stun.stunprotocol.org', 'port': 3478})
    # ext = await get_external_address(STUN_SERVERS[4])
    # print_external_address_response(STUN_SERVERS[4], ext)
    #
    # # 1) Determine external mapping via two STUN servers
    # ext1 = await get_external_address(STUN_SERVERS[0])
    # print_external_address_response(STUN_SERVERS[0], ext1)
    # ext2 = await get_external_address(STUN_SERVERS[1])
    # print_external_address_response(STUN_SERVERS[1], ext2)


if __name__ == "__main__":
    asyncio.run(main())
