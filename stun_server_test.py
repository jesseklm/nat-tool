import asyncio
import socket

from stun_server import StunServer


def is_link_ip(ip: str):
    print('is_link_ip', ip)
    for entry in socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET):
        print(entry[4][0])
        if ip == entry[4][0]:
            return True
    return False


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

    def __str__(self):
        return f'{self.server} | {self.type} | {self.result} | {self.response_host}:{self.response_port}'


async def check_nat():
    server1 = StunServer('stun.t-online.de')
    server2 = StunServer('stun.1und1.de')

    test1_s1 = StunServerTest(server1)
    await asyncio.to_thread(test1_s1.test)
    print(test1_s1)
    if not test1_s1.result:
        print('UDP blocked!')
        return

    test2_s1 = StunServerTest(server1, 'ip+port')
    await asyncio.to_thread(test2_s1.test)
    print(test2_s1)
    if is_link_ip(test1_s1.response_host):
        if test2_s1.result:
            print('Open Internet!')
        else:
            print('Symmetric Firewall!')
        return
    if test2_s1.result:
        print('Full-cone NAT!')
        return

    test1_s2 = StunServerTest(server2)
    await asyncio.to_thread(test1_s2.test)
    print(test1_s2)
    if test1_s1.response_host != test1_s2.response_host:
        print('Symmetric NAT!')
        return

    test3_s1 = StunServerTest(server1, 'port')
    await asyncio.to_thread(test3_s1.test)
    print(test3_s1)
    if test3_s1.result:
        print('Restricted cone NAT!')
    else:
        print('Restricted port NAT!')


if __name__ == '__main__':
    asyncio.run(check_nat())
