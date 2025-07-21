import array
import asyncio
import socket
import struct

from stun_server import StunServer


def is_link_ip_linux(ip_to_test: str):
    import fcntl
    print('is_link_ip_linux', ip_to_test)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b = array.array('B', b'\0' * 5120)  # 128 Interfaces × 40 Bytes
    n = struct.unpack('iL', fcntl.ioctl(
        s.fileno(), 0x8912,
        struct.pack('iL', len(b), b.buffer_info()[0])
    ))[0]
    d = b.tobytes()[:n]

    for i in range(0, n, 40):
        ip = socket.inet_ntoa(d[i + 20:i + 24])
        if ip.startswith('127.'):
            continue
        print(ip)
        if ip == ip_to_test:
            return True
    return False


def is_link_ip(ip_to_test: str):
    try:
        return is_link_ip_linux(ip_to_test)
    except ImportError:
        pass
    print('is_link_ip', ip_to_test)
    for entry in socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET):
        ip = entry[4][0]
        if ip.startswith('127.'):
            continue
        print(ip)
        if ip == ip_to_test:
            return True
    return False


class StunServerTest:
    def __init__(self, server: StunServer, type: str = 'direct'):
        self.server = server
        self.type = type
        self.result = False
        self.response = {}
        self.response_host = None
        self.response_port = None

    def test(self):
        result = self.server.test(self.type)
        self.result = result['result']
        if self.result:
            self.response = result['response']
        self.response_host = result.get('response_host')
        self.response_port = result.get('response_port')

    def get_dict(self):
        return {
            'server': self.server,
            'type': self.type,
            'result': self.result,
            'response': f'{self.response_host}:{self.response_port}',
            'local': f"{self.response.get('local_ip')}:{self.response.get('local_port')}",
        }

    def __str__(self):
        return f'{self.server} | {self.type} | {self.result} | {self.response_host}:{self.response_port}'


async def check_nat():
    server1 = StunServer('stun.t-online.de')
    server2 = StunServer('stun.1und1.de')

    test1_s1 = StunServerTest(server1)
    await asyncio.to_thread(test1_s1.test)
    yield {'test': test1_s1}
    if not test1_s1.result:
        yield {'result': 'UDP blocked!'}
        return

    test2_s1 = StunServerTest(server1, 'ip+port')
    await asyncio.to_thread(test2_s1.test)
    yield {'test': test2_s1}
    if is_link_ip(test1_s1.response_host):
        if test2_s1.result:
            yield {'result': 'Open Internet!'}
        else:
            yield {'result': 'Symmetric Firewall!'}
        return
    if test2_s1.result:
        yield {'result': 'NAT 1, Endpoint-Independent NAT, Full Cone NAT!'}
        return

    test1_s2 = StunServerTest(server2)
    await asyncio.to_thread(test1_s2.test)
    yield {'test': test1_s2}
    if test1_s1.response_host != test1_s2.response_host:
        yield {'result': 'NAT 4, Symmetric NAT!'}
        return

    test3_s1 = StunServerTest(server1, 'port')
    await asyncio.to_thread(test3_s1.test)
    yield {'test': test3_s1}
    if test3_s1.result:
        yield {'result': 'NAT 2, Address-Dependent NAT, Restricted Cone NAT!'}
    else:
        yield {'result': 'NAT 3, Address- and Port-Dependent NAT, Port Restricted Cone NAT!'}


async def check_nat_console():
    async for response in check_nat():
        if 'result' in response:
            print(response['result'])
        if 'test' in response:
            print(response['test'])


if __name__ == '__main__':
    asyncio.run(check_nat_console())
