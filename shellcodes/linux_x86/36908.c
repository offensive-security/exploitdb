/*
 * linux/x86 exit(0) - 6 bytes
 * Febriyanto Nugroho
 */

#include <stdio.h>

char shellcode[] = "\xf7\xf0"
                   "\xcd\x80"
                   "\xeb\xfa";

int main(int argc, char **argv) {
asm("jmp %0;" : "=m" (shellcode));
}