import random
import socket
import struct


class StunServer:
    MAGIC_COOKIE = 0x2112A442

    def __init__(self, host, port=3478):
        self.host = host
        self.port = port

    def __str__(self):
        return f'{self.host}:{self.port}'

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
        except (TimeoutError, socket.gaierror, ConnectionResetError, OSError) as e:
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
        attrs = []
        while offset + 4 <= len(data) and offset < end:
            attr_type, attr_len = struct.unpack('!HH', data[offset:offset + 4])
            offset += 4
            val = data[offset:offset + attr_len]
            attrs.append((attr_type, val))
            offset += attr_len + ((4 - (attr_len % 4)) % 4)

        # 1) XOR-MAPPED-ADDRESS
        for typ, val in attrs:
            if typ == 0x0020 and len(val) >= 8:
                port = struct.unpack("!H", val[2:4])[0] ^ (self.MAGIC_COOKIE >> 16)
                xip = struct.unpack("!I", val[4:8])[0] ^ self.MAGIC_COOKIE
                ip = socket.inet_ntoa(struct.pack("!I", xip))
                return ip, port

        # 2) MAPPED-ADDRESS
        for typ, val in attrs:
            if typ == 0x0001 and len(val) >= 8:
                port = struct.unpack("!H", val[2:4])[0]
                ip = socket.inet_ntoa(val[4:8])
                return ip, port

        raise ValueError("MAPPED-ADDRESS attribute not found")

    def test(self, test_type: str) -> dict:
        match test_type:
            case 'direct':
                change_ip = False
                change_port = False
            case 'port':
                change_ip = False
                change_port = True
            case 'ip':
                change_ip = True
                change_port = False
            case 'ip+port':
                change_ip = True
                change_port = True
            case _:
                raise ValueError(f"Unexpected test type: {test_type}")
        request, transaction_id = self.build_request(change_ip, change_port)
        ip, (data, host) = self.send_request(request)
        if not data:
            return {'result': False}
        try:
            parsed = self.parse_response(data, transaction_id)
        except ValueError as e:
            print(self.host, self.port, e)
            return {'result': False}
        print(test_type, parsed, ip, host, end='')
        same_ip = host[0] == ip
        if change_ip and same_ip:
            print(' ip not changed!')
            return {'result': False}
        elif not change_ip and not same_ip:
            print(' ip changed!')
            return {'result': False}
        same_port = host[1] == self.port
        if change_port and same_port:
            print(' port not changed!')
            return {'result': False}
        elif not change_port and not same_port:
            print(' port changed!')
            return {'result': False}
        print()
        return {'result': True, 'response_host': parsed[0], 'response_port': parsed[1]}
