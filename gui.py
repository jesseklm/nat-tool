import asyncio
import random
import socket
import struct
import sys

from PySide6 import QtAsyncio
from PySide6.QtWidgets import QApplication, QMainWindow, QTableWidgetItem

from ui.main import Ui_MainWindow


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


class StunServerTest:
    def __init__(self, server: StunServer, type: str = 'direct'):
        self.server = server
        self.type = type
        self.result = False
        self.response_host = None
        self.response_port = None

    def test(self):
        result = self.server.test(self.type)
        self.result = result['result']
        self.response_host = result.get('response_host')
        self.response_port = result.get('response_port')

    def get_dict(self):
        return {
            'server': self.server,
            'type': self.type,
            'result': self.result,
            'response': f'{self.response_host}:{self.response_port}'
        }


class MainWindow(Ui_MainWindow):
    def __init__(self):
        self.tasks = set()
        self.main_window = QMainWindow()
        self.setupUi(self.main_window)
        self.pushButton.clicked.connect(lambda: self.create_task(self.check_nat()))

        self.headers = ['server', 'type', 'result', 'response']
        self.tableWidget.setColumnCount(len(self.headers))
        self.tableWidget.setHorizontalHeaderLabels(self.headers)

    def create_task(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def show(self):
        self.main_window.show()

    def add_row(self, row: dict):
        row_count = self.tableWidget.rowCount()
        self.tableWidget.setRowCount(row_count + 1)
        for key, value in row.items():
            self.tableWidget.setItem(row_count, self.headers.index(key), QTableWidgetItem(str(value)))
        self.tableWidget.resizeColumnsToContents()

    @staticmethod
    def is_link_ip(ip: str):
        for entry in socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET):
            if ip == entry[4][0]:
                return True
        return False

    async def check_nat(self):
        self.tableWidget.setRowCount(0)
        server1 = StunServer('stun.t-online.de')
        server2 = StunServer('stun.1und1.de')

        test1_s1 = StunServerTest(server1)
        await asyncio.to_thread(test1_s1.test)
        self.add_row(test1_s1.get_dict())
        if not test1_s1.result:
            self.statusbar.showMessage('UDP blocked!')
            return

        test2_s1 = StunServerTest(server1, 'ip+port')
        await asyncio.to_thread(test2_s1.test)
        self.add_row(test2_s1.get_dict())
        if self.is_link_ip(test1_s1.response_host):
            if test2_s1.result:
                self.statusbar.showMessage('Open Internet!')
            else:
                self.statusbar.showMessage('Symmetric Firewall!')
            return
        if test2_s1.result:
            self.statusbar.showMessage('Full-cone NAT!')
            return

        test1_s2 = StunServerTest(server2)
        await asyncio.to_thread(test1_s2.test)
        self.add_row(test1_s2.get_dict())
        if test1_s1.response_host != test1_s2.response_host:
            self.statusbar.showMessage('Symmetric NAT!')
            return

        test3_s1 = StunServerTest(server1, 'port')
        await asyncio.to_thread(test3_s1.test)
        self.add_row(test3_s1.get_dict())
        if test3_s1.result:
            self.statusbar.showMessage('Restricted cone NAT!')
        else:
            self.statusbar.showMessage('Restricted port NAT!')


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    QtAsyncio.run(handle_sigint=True)
