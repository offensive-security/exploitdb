/*
Shellcode can be changed to work with any windows distribution by changing the address of Beep in kernel32.dll
Addresses for SP1 and SP2

-xnull
*/

#include <stdio.h>

unsigned char beepsp1[] =
"\x55\x89\xE5\x83\xEC\x18\xC7\x45\xFC"
"\x10\xC9\xEA\x77"                      //Address \x10\xC9\xEA\x77 = SP1
"\xC7\x44\x24\x04"
"\xE8\x03"                              //Length \xE8\x03 = 1000 (1 second)
"\x00\x00\xC7\x04\x24"
"\xE8\x03"                              //Frequency  \xE8\x03 = 1000
"\x00\x00\x8B\x45\xFC\xFF\xD0\xC9\xC3";

unsigned char beepsp2[] =
"\x55\x89\xE5\x83\xEC\x18\xC7\x45\xFC"
"\x53\x8A\x83\x7C"                      //Address \x53\x8A\x83\x7C = SP2
"\xC7\x44\x24\x04"
"\xD0\x03"                              //Length \xD0\x03 = 2000 (2 seconds)
"\x00\x00\xC7\x04\x24"
"\x01\x0E"                              //Frequency \x01\x0E = 3585
"\x00\x00\x8B\x45\xFC\xFF\xD0\xC9\xC3";

int main()
{
    void (*function)();
    *(long*)&function = (long)beepsp1;
    function();
}

// milw0rm.com [2006-04-14]