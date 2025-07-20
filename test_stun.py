import random
import socket
import struct

from stun import parse_mapped_or_xor_address


class StunServer:
    MAGIC_COOKIE = 0x2112A442

    def __init__(self, host, port=3478):
        self.host = host
        self.port = port

    def build_request(self, change_ip=False, change_port=False) -> tuple[bytes, bytes]:
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
        header = struct.pack('!HHI12s', msg_type, msg_length, self.MAGIC_COOKIE, transaction_id)
        return header + attrs, transaction_id

    def send_request(self, request: bytes) -> tuple[str, tuple[bytes, tuple[str, int]]]:
        try:
            ip = socket.gethostbyname(self.host)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1.0)
                dst = (ip, self.port)
                sock.sendto(request, dst)
                return ip, sock.recvfrom(2048)
        except TimeoutError as e:
            print(e)
            return '', (b'', ('', -1))

    def parse_response(self, data: bytes, transaction_id: bytes):
        if len(data) < 20:
            raise ValueError("Response too short for STUN header")
        msg_type, msg_length = struct.unpack('!HH', data[:4])
        resp_trans = data[8:20]
        if msg_type != 0x0101:
            raise ValueError(f"Unexpected STUN message type: {msg_type:#04x}")
        if resp_trans != transaction_id:
            print(resp_trans, transaction_id)
            raise ValueError("Transaction ID mismatch")
        offset = 20
        end = 20 + msg_length
        while offset + 4 <= len(data) and offset < end:
            attr_type, attr_len = struct.unpack('!HH', data[offset:offset + 4])
            offset += 4
            # Check for MAPPED-ADDRESS
            if attr_type == 0x0001 and attr_len >= 8:
                # Skip reserved byte
                family = data[offset]
                port = struct.unpack('!H', data[offset + 2:offset + 4])[0]
                ip = socket.inet_ntoa(data[offset + 4:offset + 8])
                return ip, port
            # Move to next attribute (4-byte alignment)
            offset += attr_len
            if attr_len % 4:
                offset += 4 - (attr_len % 4)

        raise ValueError("MAPPED-ADDRESS attribute not found")

    def test(self, test_type: str, change_ip=False, change_port=False) -> bool:
        request, transaction_id = self.build_request(change_ip, change_port)
        ip, (data, host) = self.send_request(request)
        if not data:
            return False
        parsed = self.parse_response(data, transaction_id)
        print(test_type, parsed, ip, host, end='')
        same_ip = host[0] == ip
        if change_ip and same_ip:
            print(' ip not changed!')
            return False
        elif not change_ip and not same_ip:
            print(' ip changed!')
            return False
        same_port = host[1] == self.port
        if change_port and same_port:
            print(' port not changed!')
            return False
        elif not change_port and not same_port:
            print(' port changed!')
            return False
        print()
        return True

    def full_test(self):
        self.test('direct')
        self.test('port', change_port=True)
        self.test('ip', change_ip=True)
        self.test('ip+port', change_ip=True, change_port=True)


def main():
    # StunServer('stun.1und1.de').full_test()
    # StunServer('stun.bluesip.net').full_test()
    # StunServer('stun.12connect.com').full_test()
    # StunServer('stun.12voip.com').full_test()
    StunServer('stun.counterpath.com').full_test()


if __name__ == "__main__":
    main()
