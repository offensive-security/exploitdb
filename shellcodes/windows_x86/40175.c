/*
	# Title : Windows x86 localhost port scanner shellcode
	# Date : 29-07-2016
	# Author : Roziul Hasan Khan Shifat
	# Tested on : Windows 7 x86 starter

*/


/*

Disassembly of section .text:

00000000 <_start>:
   0:	31 db                	xor    %ebx,%ebx
   2:	64 8b 43 30          	mov    %fs:0x30(%ebx),%eax
   6:	8b 40 0c             	mov    0xc(%eax),%eax
   9:	8b 70 14             	mov    0x14(%eax),%esi
   c:	ad                   	lods   %ds:(%esi),%eax
   d:	96                   	xchg   %eax,%esi
   e:	ad                   	lods   %ds:(%esi),%eax
   f:	8b 58 10             	mov    0x10(%eax),%ebx
  12:	31 d2                	xor    %edx,%edx
  14:	8b 53 3c             	mov    0x3c(%ebx),%edx
  17:	01 da                	add    %ebx,%edx
  19:	8b 52 78             	mov    0x78(%edx),%edx
  1c:	01 da                	add    %ebx,%edx
  1e:	8b 72 20             	mov    0x20(%edx),%esi
  21:	01 de                	add    %ebx,%esi
  23:	31 c9                	xor    %ecx,%ecx

00000025 <getp>:
  25:	41                   	inc    %ecx
  26:	ad                   	lods   %ds:(%esi),%eax
  27:	01 d8                	add    %ebx,%eax
  29:	81 38 47 65 74 50    	cmpl   $0x50746547,(%eax)
  2f:	75 f4                	jne    25 <getp>
  31:	81 78 04 72 6f 63 41 	cmpl   $0x41636f72,0x4(%eax)
  38:	75 eb                	jne    25 <getp>
  3a:	81 78 08 64 64 72 65 	cmpl   $0x65726464,0x8(%eax)
  41:	75 e2                	jne    25 <getp>
  43:	8b 72 1c             	mov    0x1c(%edx),%esi
  46:	01 de                	add    %ebx,%esi
  48:	8b 14 8e             	mov    (%esi,%ecx,4),%edx
  4b:	01 da                	add    %ebx,%edx
  4d:	31 f6                	xor    %esi,%esi
  4f:	89 d6                	mov    %edx,%esi
  51:	89 df                	mov    %ebx,%edi
  53:	31 c9                	xor    %ecx,%ecx
  55:	68 6c 6f 63 41       	push   $0x41636f6c
  5a:	88 4c 24 03          	mov    %cl,0x3(%esp)
  5e:	68 61 6c 41 6c       	push   $0x6c416c61
  63:	68 47 6c 6f 62       	push   $0x626f6c47
  68:	54                   	push   %esp
  69:	53                   	push   %ebx
  6a:	ff d2                	call   *%edx
  6c:	83 c4 0c             	add    $0xc,%esp
  6f:	31 c9                	xor    %ecx,%ecx
  71:	b1 20                	mov    $0x20,%cl
  73:	51                   	push   %ecx
  74:	31 c9                	xor    %ecx,%ecx
  76:	51                   	push   %ecx
  77:	ff d0                	call   *%eax
  79:	89 f1                	mov    %esi,%ecx
  7b:	89 c6                	mov    %eax,%esi
  7d:	89 0e                	mov    %ecx,(%esi)
  7f:	31 c9                	xor    %ecx,%ecx
  81:	68 65 65 41 41       	push   $0x41416565
  86:	88 4c 24 02          	mov    %cl,0x2(%esp)
  8a:	68 61 6c 46 72       	push   $0x72466c61
  8f:	68 47 6c 6f 62       	push   $0x626f6c47
  94:	54                   	push   %esp
  95:	57                   	push   %edi
  96:	8b 16                	mov    (%esi),%edx
  98:	ff d2                	call   *%edx
  9a:	83 c4 0c             	add    $0xc,%esp
  9d:	89 46 04             	mov    %eax,0x4(%esi)
  a0:	31 c9                	xor    %ecx,%ecx
  a2:	51                   	push   %ecx
  a3:	68 61 72 79 41       	push   $0x41797261
  a8:	68 4c 69 62 72       	push   $0x7262694c
  ad:	68 4c 6f 61 64       	push   $0x64616f4c
  b2:	54                   	push   %esp
  b3:	57                   	push   %edi
  b4:	8b 16                	mov    (%esi),%edx
  b6:	ff d2                	call   *%edx
  b8:	83 c4 0c             	add    $0xc,%esp
  bb:	89 46 08             	mov    %eax,0x8(%esi)
  be:	31 c9                	xor    %ecx,%ecx
  c0:	68 6c 6c 41 41       	push   $0x41416c6c
  c5:	88 4c 24 02          	mov    %cl,0x2(%esp)
  c9:	68 72 74 2e 64       	push   $0x642e7472
  ce:	68 6d 73 76 63       	push   $0x6376736d
  d3:	54                   	push   %esp
  d4:	ff d0                	call   *%eax
  d6:	83 c4 0c             	add    $0xc,%esp
  d9:	89 c7                	mov    %eax,%edi
  db:	31 c9                	xor    %ecx,%ecx
  dd:	51                   	push   %ecx
  de:	68 74 66 5f 73       	push   $0x735f6674
  e3:	68 70 72 69 6e       	push   $0x6e697270
  e8:	54                   	push   %esp
  e9:	50                   	push   %eax
  ea:	8b 16                	mov    (%esi),%edx
  ec:	ff d2                	call   *%edx
  ee:	83 c4 08             	add    $0x8,%esp
  f1:	89 46 0c             	mov    %eax,0xc(%esi)
  f4:	31 c9                	xor    %ecx,%ecx
  f6:	51                   	push   %ecx
  f7:	68 65 78 69 74       	push   $0x74697865
  fc:	54                   	push   %esp
  fd:	57                   	push   %edi
  fe:	8b 16                	mov    (%esi),%edx
 100:	ff d2                	call   *%edx
 102:	83 c4 08             	add    $0x8,%esp
 105:	89 46 10             	mov    %eax,0x10(%esi)
 108:	8b 56 08             	mov    0x8(%esi),%edx
 10b:	31 c9                	xor    %ecx,%ecx
 10d:	68 64 6c 6c 41       	push   $0x416c6c64
 112:	88 4c 24 03          	mov    %cl,0x3(%esp)
 116:	68 6b 33 32 2e       	push   $0x2e32336b
 11b:	68 77 73 6f 63       	push   $0x636f7377
 120:	54                   	push   %esp
 121:	ff d2                	call   *%edx
 123:	83 c4 0c             	add    $0xc,%esp
 126:	89 c7                	mov    %eax,%edi
 128:	31 c9                	xor    %ecx,%ecx
 12a:	68 75 70 41 41       	push   $0x41417075
 12f:	88 4c 24 02          	mov    %cl,0x2(%esp)
 133:	68 74 61 72 74       	push   $0x74726174
 138:	68 57 53 41 53       	push   $0x53415357
 13d:	54                   	push   %esp
 13e:	50                   	push   %eax
 13f:	8b 16                	mov    (%esi),%edx
 141:	ff d2                	call   *%edx
 143:	89 46 14             	mov    %eax,0x14(%esi)
 146:	83 c4 0c             	add    $0xc,%esp
 149:	68 65 74 41 41       	push   $0x41417465
 14e:	31 c9                	xor    %ecx,%ecx
 150:	88 4c 24 02          	mov    %cl,0x2(%esp)
 154:	68 73 6f 63 6b       	push   $0x6b636f73
 159:	54                   	push   %esp
 15a:	57                   	push   %edi
 15b:	8b 16                	mov    (%esi),%edx
 15d:	ff d2                	call   *%edx
 15f:	89 46 18             	mov    %eax,0x18(%esi)
 162:	83 c4 08             	add    $0x8,%esp
 165:	68 65 63 74 41       	push   $0x41746365
 16a:	31 c9                	xor    %ecx,%ecx
 16c:	88 4c 24 03          	mov    %cl,0x3(%esp)
 170:	68 63 6f 6e 6e       	push   $0x6e6e6f63
 175:	54                   	push   %esp
 176:	57                   	push   %edi
 177:	8b 16                	mov    (%esi),%edx
 179:	ff d2                	call   *%edx
 17b:	83 c4 08             	add    $0x8,%esp
 17e:	89 46 1c             	mov    %eax,0x1c(%esi)
 181:	31 c9                	xor    %ecx,%ecx
 183:	68 6b 65 74 41       	push   $0x4174656b
 188:	88 4c 24 03          	mov    %cl,0x3(%esp)
 18c:	68 65 73 6f 63       	push   $0x636f7365
 191:	68 63 6c 6f 73       	push   $0x736f6c63
 196:	54                   	push   %esp
 197:	57                   	push   %edi
 198:	8b 16                	mov    (%esi),%edx
 19a:	ff d2                	call   *%edx
 19c:	83 c4 0c             	add    $0xc,%esp
 19f:	89 46 08             	mov    %eax,0x8(%esi)
 1a2:	8b 56 14             	mov    0x14(%esi),%edx
 1a5:	31 c9                	xor    %ecx,%ecx
 1a7:	66 b9 90 01          	mov    $0x190,%cx
 1ab:	29 cc                	sub    %ecx,%esp
 1ad:	66 b9 02 02          	mov    $0x202,%cx
 1b1:	8d 1c 24             	lea    (%esp),%ebx
 1b4:	53                   	push   %ebx
 1b5:	51                   	push   %ecx
 1b6:	ff d2                	call   *%edx
 1b8:	31 ff                	xor    %edi,%edi

000001ba <scan>:
 1ba:	31 d2                	xor    %edx,%edx
 1bc:	b2 06                	mov    $0x6,%dl
 1be:	52                   	push   %edx
 1bf:	83 ea 05             	sub    $0x5,%edx
 1c2:	52                   	push   %edx
 1c3:	42                   	inc    %edx
 1c4:	52                   	push   %edx
 1c5:	8b 56 18             	mov    0x18(%esi),%edx
 1c8:	ff d2                	call   *%edx
 1ca:	89 c3                	mov    %eax,%ebx
 1cc:	31 d2                	xor    %edx,%edx
 1ce:	52                   	push   %edx
 1cf:	52                   	push   %edx
 1d0:	52                   	push   %edx
 1d1:	52                   	push   %edx
 1d2:	31 c0                	xor    %eax,%eax
 1d4:	b0 ff                	mov    $0xff,%al
 1d6:	40                   	inc    %eax
 1d7:	f7 e7                	mul    %edi
 1d9:	c6 04 24 02          	movb   $0x2,(%esp)
 1dd:	89 44 24 02          	mov    %eax,0x2(%esp)
 1e1:	8d 14 24             	lea    (%esp),%edx
 1e4:	31 c9                	xor    %ecx,%ecx
 1e6:	b1 10                	mov    $0x10,%cl
 1e8:	53                   	push   %ebx
 1e9:	51                   	push   %ecx
 1ea:	52                   	push   %edx
 1eb:	53                   	push   %ebx
 1ec:	8b 46 1c             	mov    0x1c(%esi),%eax
 1ef:	ff d0                	call   *%eax
 1f1:	5b                   	pop    %ebx
 1f2:	83 c4 10             	add    $0x10,%esp
 1f5:	31 c9                	xor    %ecx,%ecx
 1f7:	51                   	push   %ecx
 1f8:	68 20 20 20 0a       	push   $0xa202020
 1fd:	68 3e 20 25 64       	push   $0x6425203e
 202:	68 25 64 20 2d       	push   $0x2d206425
 207:	54                   	push   %esp
 208:	59                   	pop    %ecx
 209:	50                   	push   %eax
 20a:	57                   	push   %edi
 20b:	51                   	push   %ecx
 20c:	8b 46 0c             	mov    0xc(%esi),%eax
 20f:	ff d0                	call   *%eax
 211:	83 c4 10             	add    $0x10,%esp
 214:	53                   	push   %ebx
 215:	8b 46 08             	mov    0x8(%esi),%eax
 218:	ff d0                	call   *%eax
 21a:	47                   	inc    %edi
 21b:	83 ff 65             	cmp    $0x65,%edi
 21e:	75 9a                	jne    1ba <scan>
 220:	8b 46 04             	mov    0x4(%esi),%eax
 223:	8b 7e 10             	mov    0x10(%esi),%edi
 226:	56                   	push   %esi
 227:	ff d0                	call   *%eax
 229:	50                   	push   %eax
 22a:	ff d7                	call   *%edi

*/


/*

section .text
	global _start
_start:

xor ebx,ebx
mov eax,[fs:ebx+0x30]
mov eax,[eax+0xc]
mov esi,[eax+0x14]
lodsd
xchg esi,eax
lodsd
mov ebx,[eax+0x10] ;kernel32.dll base address


xor edx,edx
mov edx,[ebx+0x3c]
add edx,ebx
mov edx,[edx+0x78]
add edx,ebx ;IMAGE_EXPORT_DIRECTORY


mov esi,[edx+0x20]
add esi,ebx ;AddressOfNames

xor ecx,ecx
getp:
inc ecx
lodsd
add eax,ebx
cmp dword [eax],'GetP'
jnz getp
cmp dword [eax+4],'rocA'
jnz getp
cmp dword [eax+8],'ddre'
jnz getp

mov esi,[edx+0x1c]
add esi,ebx ;AddressOfFunctions


mov edx,[esi+ecx*4]
add edx,ebx ;GetProcAddress()


;----------------------------------

xor esi,esi
mov esi,edx ;GetProcAddress()
mov edi,ebx ;kernel32 base address

;------------------------------

;finding address of GlobalAlloc()
xor ecx,ecx
push 0x41636f6c
mov [esp+3],byte cl
push 0x6c416c61
push 0x626f6c47

push esp
push ebx
call edx
add esp,12
;---------------------------
;GlobalAlloc(0x00,4*8) sizeof every function address 4 byte and i will store address of 8 functions

xor ecx,ecx
mov cl,32
push ecx
xor ecx,ecx
push ecx
call eax

;--------------------------------

mov ecx,esi
mov esi,eax

mov [esi],dword ecx ;GetProcAddress() at offset 0

;----------------------------------
;finding address of GlobalFree()
xor ecx,ecx
push 0x41416565
mov [esp+2],byte cl
push 0x72466c61
push 0x626f6c47

push esp
push edi
mov edx,dword [esi]
call edx
add esp,12

;----------------------
mov [esi+4],dword eax ;GlobalFree() at offset 4
;------------------------
;finding address of LoadLibraryA()
xor ecx,ecx
push ecx
push 0x41797261
push 0x7262694c
push 0x64616f4c

push esp
push edi
mov edx,dword [esi]
call edx

add esp,12

;----------------------
mov [esi+8],dword eax ;LoadLibraryA() at offset 8
;------------------------

;loading msvcrt.dll
xor ecx,ecx
push 0x41416c6c
mov [esp+2],byte cl
push 0x642e7472
push 0x6376736d

push esp
call eax
add esp,12

;-------------------------
mov edi,eax ;msvcrt.dll base address
;-----------------------
;finding address of printf()
xor ecx,ecx
push ecx
push 0x735f6674
push 0x6e697270

push esp
push eax
mov edx,dword [esi]
call edx
add esp,8
;----------------------
mov [esi+12],dword eax ;printf() at offset 12
;---------------------
;finding address of exit()
xor ecx,ecx
push ecx
push 'exit'
push esp
push edi
mov edx,dword [esi]
call edx
add esp,8
;---------------------
mov [esi+16],dword eax ;exit() at offset 16
;--------------------------------
;loading wsock32.dll

mov edx,dword [esi+8]
xor ecx,ecx
push 0x416c6c64
mov [esp+3],byte cl
push 0x2e32336b
push 0x636f7377

push esp
call edx
add esp,12
;----------------------
mov edi,eax ;wsock32.dll
;---------------------
;finding address of WSAStartup()
xor ecx,ecx
push 0x41417075
mov [esp+2],byte cl
push 0x74726174
push 0x53415357

push esp
push eax
mov edx,dword [esi]
call edx
;---------------------
mov [esi+20],dword eax ;WSAStartup() at offset 20
;----------------------
add esp,12
;finding address of socket()
push 0x41417465
xor ecx,ecx
mov [esp+2],byte cl
push 0x6b636f73

push esp
push edi
mov edx,dword [esi]
call edx
;-------------------------------
mov [esi+24],dword eax ;socket() at offset 24
;------------------------------
add esp,8
;finding address connect()
push 0x41746365
xor ecx,ecx
mov [esp+3],byte cl
push 0x6e6e6f63

push esp
push edi
mov edx,dword [esi]
call edx
add esp,8
;-------------------------
mov [esi+28],dword eax ;connect() at offset 28
;---------------------------------
;finding address of closesocket()
xor ecx,ecx
push 0x4174656b
mov [esp+3],byte cl
push 0x636f7365
push 0x736f6c63

push esp
push edi
mov edx,dword [esi]
call edx
add esp,12
;---------------------------
mov [esi+8],dword eax ;closesocket() at offset 8
;---------------------------------

;-------------------
;WSAStartup(514,&wsa)
mov edx,dword [esi+20] ;edx=WSAStartup()
xor ecx,ecx
mov cx,400
sub esp,ecx
mov cx,514
lea ebx,[esp]
push ebx
push ecx
call edx


;---------------------
xor edi,edi ;port scanning start from 0 - 100

scan:
;socket(2,1,6)
xor edx,edx
mov dl,6
push edx
sub edx,5
push edx
inc edx
push edx
mov edx,dword [esi+24] ;socket()
call edx
;----------------------
;connect()
mov ebx,eax ;SOCKET
xor edx,edx
push edx
push edx
push edx
push edx

xor eax,eax
mov al,255
inc eax
mul edi
mov [esp],byte 2
mov [esp+2],word eax
;mov [esp+4],dword 0x81e8a8c0 ;Use it to scan foreign host


lea edx,[esp]

xor ecx,ecx
mov cl,16
push ebx
push ecx
push edx
push ebx

mov eax,[esi+28] ;connect()
call eax

pop ebx ;SOCKET
add esp,16
xor ecx,ecx
push ecx
push 0x0a202020
push 0x6425203e
push 0x2d206425


push esp
pop ecx

push eax
push edi
push ecx
mov eax,dword [esi+12] ;printf()
call eax

add esp,16
push ebx ;SOCKET
mov eax,dword [esi+8] ;closesocket()
call eax

inc edi
cmp edi,101
jne scan



mov eax,dword [esi+4] ;GlobalFree()
mov edi,dword [esi+16] ;exit()

push esi
call eax

push eax
call edi

*/

#include<stdio.h>
#include<string.h>


char shellcode[]="\x31\xdb\x64\x8b\x43\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x31\xd2\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x31\xf6\x89\xd6\x89\xdf\x31\xc9\x68\x6c\x6f\x63\x41\x88\x4c\x24\x03\x68\x61\x6c\x41\x6c\x68\x47\x6c\x6f\x62\x54\x53\xff\xd2\x83\xc4\x0c\x31\xc9\xb1\x20\x51\x31\xc9\x51\xff\xd0\x89\xf1\x89\xc6\x89\x0e\x31\xc9\x68\x65\x65\x41\x41\x88\x4c\x24\x02\x68\x61\x6c\x46\x72\x68\x47\x6c\x6f\x62\x54\x57\x8b\x16\xff\xd2\x83\xc4\x0c\x89\x46\x04\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x57\x8b\x16\xff\xd2\x83\xc4\x0c\x89\x46\x08\x31\xc9\x68\x6c\x6c\x41\x41\x88\x4c\x24\x02\x68\x72\x74\x2e\x64\x68\x6d\x73\x76\x63\x54\xff\xd0\x83\xc4\x0c\x89\xc7\x31\xc9\x51\x68\x74\x66\x5f\x73\x68\x70\x72\x69\x6e\x54\x50\x8b\x16\xff\xd2\x83\xc4\x08\x89\x46\x0c\x31\xc9\x51\x68\x65\x78\x69\x74\x54\x57\x8b\x16\xff\xd2\x83\xc4\x08\x89\x46\x10\x8b\x56\x08\x31\xc9\x68\x64\x6c\x6c\x41\x88\x4c\x24\x03\x68\x6b\x33\x32\x2e\x68\x77\x73\x6f\x63\x54\xff\xd2\x83\xc4\x0c\x89\xc7\x31\xc9\x68\x75\x70\x41\x41\x88\x4c\x24\x02\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50\x8b\x16\xff\xd2\x89\x46\x14\x83\xc4\x0c\x68\x65\x74\x41\x41\x31\xc9\x88\x4c\x24\x02\x68\x73\x6f\x63\x6b\x54\x57\x8b\x16\xff\xd2\x89\x46\x18\x83\xc4\x08\x68\x65\x63\x74\x41\x31\xc9\x88\x4c\x24\x03\x68\x63\x6f\x6e\x6e\x54\x57\x8b\x16\xff\xd2\x83\xc4\x08\x89\x46\x1c\x31\xc9\x68\x6b\x65\x74\x41\x88\x4c\x24\x03\x68\x65\x73\x6f\x63\x68\x63\x6c\x6f\x73\x54\x57\x8b\x16\xff\xd2\x83\xc4\x0c\x89\x46\x08\x8b\x56\x14\x31\xc9\x66\xb9\x90\x01\x29\xcc\x66\xb9\x02\x02\x8d\x1c\x24\x53\x51\xff\xd2\x31\xff\x31\xd2\xb2\x06\x52\x83\xea\x05\x52\x42\x52\x8b\x56\x18\xff\xd2\x89\xc3\x31\xd2\x52\x52\x52\x52\x31\xc0\xb0\xff\x40\xf7\xe7\xc6\x04\x24\x02\x89\x44\x24\x02\x8d\x14\x24\x31\xc9\xb1\x10\x53\x51\x52\x53\x8b\x46\x1c\xff\xd0\x5b\x83\xc4\x10\x31\xc9\x51\x68\x20\x20\x20\x0a\x68\x3e\x20\x25\x64\x68\x25\x64\x20\x2d\x54\x59\x50\x57\x51\x8b\x46\x0c\xff\xd0\x83\xc4\x10\x53\x8b\x46\x08\xff\xd0\x47\x83\xff\x65\x75\x9a\x8b\x46\x04\x8b\x7e\x10\x56\xff\xd0\x50\xff\xd7";



main()
{

printf("shellcode length %ld\n",(unsigned)strlen(shellcode));
(* (int(*)()) shellcode) ();
}